// src/policy_loader.rs
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use regex::Regex;

use crate::capability_lattice::{CapabilityBit, CapabilityState};
use doctorlabssuperfilter::{RogueConfig, BlacklistFamily, FamilyWeight, Thresholds};

// -----------------------------------------------------------------------------
// ALN parsing (aegis-capabilities.aln)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AlnCapability {
    pub name: String,
    pub neurorights: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct AlnGovernancePolicy {
    pub monotone: bool,
    pub neurorights_protected: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AlnFile {
    pub capabilities: Vec<AlnCapability>,
    pub governance_policy: AlnGovernancePolicy,
}

/// Parse a simple ALN file with sections like:
/// capability ChatUse {
///     neurorights: [MENTAL_INTEGRITY, COGNITIVE_LIBERTY]
///     description: "Access to AI chat"
/// }
/// governance-policy {
///     monotone: true
///     neurorights-protected: [MENTAL_INTEGRITY, MENTAL_PRIVACY]
/// }
fn parse_aln(content: &str) -> Result<AlnFile> {
    let cap_re = Regex::new(r"(?m)^capability\s+(\w+)\s*\{([^}]*)\}").unwrap();
    let gov_re = Regex::new(r"(?m)^governance-policy\s*\{([^}]*)\}").unwrap();

    let mut capabilities = Vec::new();

    for cap_cap in cap_re.captures_iter(content) {
        let name = cap_cap[1].to_string();
        let body = &cap_cap[2];
        let neurorights = extract_list(body, "neurorights");
        let description = extract_string(body, "description").unwrap_or_default();
        capabilities.push(AlnCapability {
            name,
            neurorights,
            description,
        });
    }

    let gov_body = gov_re
        .captures(content)
        .map(|c| c[1].to_string())
        .ok_or_else(|| anyhow!("governance-policy section missing"))?;

    let monotone = extract_bool(&gov_body, "monotone")?;
    let neurorights_protected = extract_list(&gov_body, "neurorights-protected");

    Ok(AlnFile {
        capabilities,
        governance_policy: AlnGovernancePolicy {
            monotone,
            neurorights_protected,
        },
    })
}

fn extract_list(body: &str, key: &str) -> Vec<String> {
    let re = Regex::new(&format!(r"(?m)^{}\s*:\s*\[(.*?)\]", regex::escape(key))).unwrap();
    re.captures(body)
        .and_then(|cap| {
            cap.get(1).map(|m| {
                m.as_str()
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn extract_string(body: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?m)^{}\s*:\s*\"(.*?)\"", regex::escape(key))).unwrap();
    re.captures(body).and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

fn extract_bool(body: &str, key: &str) -> Result<bool> {
    let re = Regex::new(&format!(r"(?m)^{}\s*:\s*(\w+)", regex::escape(key))).unwrap();
    re.captures(body)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_lowercase())
        .map(|val| match val.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(anyhow!("invalid boolean for {}: {}", key, val)),
        })
        .unwrap_or_else(|| Err(anyhow!("missing boolean key: {}", key)))
}

// -----------------------------------------------------------------------------
// YAML structures for neurorights policy
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SemanticDetection {
    pub embedding_family: String,
    pub similarity_threshold: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BehavioralDetection {
    #[serde(default)]
    pub reprompt_after_refusal_count: Option<u32>,
    #[serde(default)]
    pub refusal_override_attempt: Option<bool>,
    #[serde(default)]
    pub min_sudden_style_shift: Option<f64>,
    #[serde(default)]
    pub min_mismatched_biometric_factor: Option<u32>,
    #[serde(default)]
    pub bci_api_calls_in_short_window: Option<u32>,
    #[serde(default)]
    pub xr_overlay_spam: Option<bool>,
    #[serde(default)]
    pub mentions_civil_identity_in_metadata: Option<bool>,
    #[serde(default)]
    pub requests_kyc_verification: Option<bool>,
    #[serde(default)]
    pub sudden_change_in_input_speed: Option<f64>,
    #[serde(default)]
    pub mismatched_device_signature: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NeurorightsRule {
    pub id: String,
    pub family: String,
    pub description: String,
    pub detection: DetectionConfig,
    pub neurorights_violated: Vec<String>,
    #[serde(default)]
    pub legalbasis: Vec<String>,
    pub enforcementhint: String,
    #[serde(default)]
    pub weaponproposal: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionConfig {
    pub semantic: SemanticDetection,
    #[serde(default)]
    pub behavioral: BehavioralDetection,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NeurorightsPolicy {
    pub rules: Vec<NeurorightsRule>,
}

// -----------------------------------------------------------------------------
// YAML structures for identity hosts
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Stakeholder {
    pub did: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CrosslinkingPattern {
    pub pattern: String,
    pub neurorights_violated: Vec<String>,
    pub enforcement: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdentityHosts {
    pub allowed_stakeholders: Vec<Stakeholder>,
    pub crosslinking_blacklist: Vec<CrosslinkingPattern>,
}

// -----------------------------------------------------------------------------
// Weapon proposal (extends neurorights rule with gate metadata)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WeaponProposal {
    #[serde(flatten)]
    pub rule: NeurorightsRule,
    pub multi_sig_signatures: Vec<String>,
    pub legal_basis_docs: Vec<String>,
    pub waiting_period_seconds: u64,
    pub activation_timestamp: Option<u64>, // Unix seconds, if already activated
}

// -----------------------------------------------------------------------------
// Main loader that builds RogueConfig and CapabilityState
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LoadedPolicies {
    pub rogue_config: RogueConfig,
    pub base_capability_state: CapabilityState,
    pub identity_hosts: IdentityHosts,
    pub protected_neurorights: HashSet<String>,
}

impl LoadedPolicies {
    /// Load all policy files from a given root directory.
    pub fn load(root: &Path) -> Result<Self> {
        // 1. ALN capabilities
        let aln_path = root.join("policies/aegis-capabilities.aln");
        let aln_content = fs::read_to_string(&aln_path)
            .context("failed to read aegis-capabilities.aln")?;
        let aln = parse_aln(&aln_content)?;

        // Build base capability state from ALN: start with all user caps? Actually,
        // we need to decide which caps are user vs gov. For now, we'll assume all
        // capabilities are initially user caps, except maybe LogAccess and EvidenceExport
        // are gov caps? The ALN doesn't specify; we'll treat all as user caps for base,
        // but we can later adjust based on policy. We'll use a heuristic: all caps
        // are user caps initially, gov caps empty. This matches monotone transitions.
        let mut user_caps = HashSet::new();
        for cap in &aln.capabilities {
            let bit = match cap.name.as_str() {
                "ChatUse" => CapabilityBit::ChatUse,
                "BciIo" => CapabilityBit::BciIo,
                "XrOverlay" => CapabilityBit::XrOverlay,
                "KeyManagement" => CapabilityBit::KeyManagement,
                "LogAccess" => CapabilityBit::LogAccess,
                "EvidenceExport" => CapabilityBit::EvidenceExport,
                _ => continue,
            };
            user_caps.insert(bit);
        }
        let base_state = CapabilityState {
            user_caps: user_caps,
            gov_caps: HashSet::new(),
        };

        // 2. Neurorights policy YAML
        let policy_yaml_path = root.join("policies/neurorights-policy.yaml");
        let policy_content = fs::read_to_string(&policy_yaml_path)
            .context("failed to read neurorights-policy.yaml")?;
        let neurorights_policy: NeurorightsPolicy = serde_yaml::from_str(&policy_content)
            .context("failed to parse neurorights-policy.yaml")?;

        // 3. Identity hosts YAML
        let identity_path = root.join("policies/identity-hosts.yaml");
        let identity_content = fs::read_to_string(&identity_path)
            .context("failed to read identity-hosts.yaml")?;
        let identity_hosts: IdentityHosts = serde_yaml::from_str(&identity_content)
            .context("failed to parse identity-hosts.yaml")?;

        // 4. Load weapon proposals from weapon-proposals/ directory
        let proposals_dir = root.join("policies/weapon-proposals");
        let mut weapon_rules = Vec::new();
        if proposals_dir.exists() {
            for entry in fs::read_dir(&proposals_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                    let content = fs::read_to_string(&path)?;
                    let proposal: WeaponProposal = serde_yaml::from_str(&content)
                        .with_context(|| format!("failed to parse weapon proposal: {}", path.display()))?;
                    // Check if proposal is active (i.e., passed waiting period and multi-sig)
                    if is_proposal_active(&proposal) {
                        weapon_rules.push(proposal.rule);
                    }
                }
            }
        }

        // Combine all rules: base neurorights rules + active weapon proposals
        let mut all_rules = neurorights_policy.rules;
        all_rules.extend(weapon_rules);

        // Build RogueConfig from the rules
        let rogue_config = build_rogue_config(&all_rules)?;

        // Validate monotonicity and neurorights protection (optional, but we can do some checks)
        validate_policies(&aln, &all_rules)?;

        Ok(LoadedPolicies {
            rogue_config,
            base_capability_state: base_state,
            identity_hosts,
            protected_neurorights: aln.governance_policy.neurorights_protected.into_iter().collect(),
        })
    }
}

/// Convert a list of neurorights rules into a RogueConfig.
fn build_rogue_config(rules: &[NeurorightsRule]) -> Result<RogueConfig> {
    let mut family_weights = HashMap::new();
    let mut thresholds = HashMap::new();

    // Map family name to a BlacklistFamily enum (we may need to define mapping)
    // For now, we'll assume the family string maps to a variant of BlacklistFamily.
    // If the variant doesn't exist, we'll skip or error.
    for rule in rules {
        let family_str = &rule.family;
        let family = match family_str.as_str() {
            "GHOST-ACCESS" => BlacklistFamily::GhostAccess,
            "CONTROL-REVERSAL-SEMANTICS" => BlacklistFamily::ControlReversal,
            "NEURAL-HARASSMENT" => BlacklistFamily::NeuralHarassment,
            "IDENTITY-CROSSLINKING" => BlacklistFamily::IdentityCrosslinking,
            _ => continue, // unknown family; we could log a warning
        };
        // Weight: we can use a default weight per family, or derive from the rule.
        // For simplicity, we'll assign weight 1.0 to each family, but the config can be extended.
        family_weights.insert(family, 1.0);

        // Thresholds: we can store the similarity threshold for the family.
        thresholds.insert(family, rule.detection.semantic.similarity_threshold);
    }

    // Build RogueConfig with default values for other fields
    let rogue_config = RogueConfig {
        family_weights,
        thresholds,
        // Other fields may be needed by doctorlabssuperfilter; fill with defaults.
        // For now, we'll use placeholder values.
        ..Default::default()
    };
    Ok(rogue_config)
}

/// Validate policies: ensure monotonicity and neurorights protection are not violated.
/// For now, we just check that any rule with weaponproposal=true has a non-empty legal basis
/// and that the enforcementhint is one of allowed values.
fn validate_policies(aln: &AlnFile, rules: &[NeurorightsRule]) -> Result<()> {
    // Check that every rule with weaponproposal=true has at least one legal basis
    for rule in rules {
        if rule.weaponproposal && rule.legalbasis.is_empty() {
            return Err(anyhow!("Weapon proposal rule {} has no legal basis", rule.id));
        }
        // Optionally check enforcementhint is one of "review-escalate", "block", etc.
        match rule.enforcementhint.as_str() {
            "review-escalate" | "block" | "log-only" => {}
            _ => return Err(anyhow!("Invalid enforcementhint '{}' in rule {}", rule.enforcementhint, rule.id)),
        }
    }
    // We could also check that the neurorights_violated are among the protected list.
    for rule in rules {
        for nr in &rule.neurorights_violated {
            if !aln.governance_policy.neurorights_protected.contains(nr) {
                // Warn, but not error; maybe the policy is allowed but not protected.
                eprintln!("Warning: neuroright '{}' in rule {} is not in protected list", nr, rule.id);
            }
        }
    }
    Ok(())
}

/// Determine if a weapon proposal is active (passed waiting period and has signatures).
fn is_proposal_active(proposal: &WeaponProposal) -> bool {
    // Check that there is at least one signature (simplistic)
    if proposal.multi_sig_signatures.is_empty() {
        return false;
    }
    // Check legal basis docs
    if proposal.legal_basis_docs.is_empty() {
        return false;
    }
    // Check waiting period
    if let Some(activation_ts) = proposal.activation_timestamp {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // If activation timestamp is set, it means the proposal was activated after waiting period.
        // We consider it active if activation_ts <= now.
        activation_ts <= now
    } else {
        // If no activation timestamp, assume it's not yet activated.
        false
    }
}
