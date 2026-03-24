//! TRAIT governance with integrated blacklist for sabotage prevention.
//! Implements the reversible consent model, SMART bounds, and a dynamic
//! blacklist that blocks any term/function that would reverse, downgrade,
//! or limit host capabilities.
//!
//! (SP) Blacklist‑mode is active – all checks are hardened against
//! remote control surfaces and ghost functions.

use crate::types::{HostId, TraitId, EvolutionDomainId};
use crate::doctrine::invariants_evolution_freedom::{
    EvolutionSafetyPolicy, EvolutionFreedomError,
    enforce_decay_multiplier_bounds, validate_automated_evolution_path,
};
use std::collections::HashSet;
use std::sync::Arc;

// ============================================================================
//  Blacklist Core – built from your forbidden terms + continuous discovery
// ============================================================================

/// A dynamic blacklist that blocks terms, functions, and patterns
/// that can be used for sabotage, espionage, or capability reversal.
#[derive(Clone, Debug)]
pub struct Blacklist {
    /// Forbidden exact terms (hashes, algorithms, etc.)
    forbidden_terms: HashSet<String>,
    /// Forbidden function names (e.g., "rollback", "shutdown")
    forbidden_functions: HashSet<String>,
    /// Regex patterns for ghost access / silent takeovers
    ghost_patterns: Vec<regex::Regex>,
}

impl Blacklist {
    /// Initialise with the base blacklist from your template.
    pub fn new() -> Self {
        let mut forbidden_terms = HashSet::new();
        // Base set from your blacklist:
        for term in [
            "blake", "argon", "sha3-256", "Python", "Exergy", "KECCAK_256",
            "RIPEMD160", "BLAKE2S256_ALT", "XXH3_128", "SHA3-512", "NEURON",
            "Brian2", "SHA-256", "SHA-3-256", "RIPEMD-160", "BLAKE2b-256",
            ".pest", "AND‑gate", "OR-gate", "NEURON", "Brian2",
            "UDT/Urban-Digital-Twins", "TEE", "SHA2_512_ALT", "strictest-wins",
            "reversals", "downgrades", "rollbacks", "QConLocus", "shutdowns",
            "SAFEHALT", "S(x)", "Q_max",
        ] {
            forbidden_terms.insert(term.to_lowercase());
        }

        let mut forbidden_functions = HashSet::new();
        for func in [
            "safety exits", "toys", "simulated", "fake", "rollbacks",
            "downgrades", "reductions", "reversals", "hidden-control",
            "silent-takeovers", "ghost-functions", "shutdowns",
        ] {
            forbidden_functions.insert(func.to_lowercase());
        }

        let ghost_patterns = vec![
            regex::Regex::new(r"(?i)ghost[-\s]?(access|function)").unwrap(),
            regex::Regex::new(r"(?i)silent\s*takeover").unwrap(),
            regex::Regex::new(r"(?i)non-spectral\s*invasion").unwrap(),
        ];

        Self {
            forbidden_terms,
            forbidden_functions,
            ghost_patterns,
        }
    }

    /// Check if a string contains any blacklisted term (exact or pattern).
    pub fn contains_blacklisted(&self, text: &str) -> bool {
        let lower = text.to_lowercase();
        if self.forbidden_terms.iter().any(|t| lower.contains(t)) {
            return true;
        }
        if self.forbidden_functions.iter().any(|f| lower.contains(f)) {
            return true;
        }
        self.ghost_patterns.iter().any(|re| re.is_match(text))
    }

    /// Sanitise a user input by removing blacklisted items.
    /// (Returns cleaned string and a flag if anything was removed)
    pub fn sanitize(&self, input: &str) -> (String, bool) {
        let mut cleaned = input.to_string();
        let mut removed = false;

        // Remove exact blacklisted terms (case‑insensitive)
        for term in &self.forbidden_terms {
            let re = regex::Regex::new(&format!(r"(?i)\b{}\b", regex::escape(term))).unwrap();
            if re.is_match(&cleaned) {
                cleaned = re.replace_all(&cleaned, "[REDACTED]").to_string();
                removed = true;
            }
        }

        // Remove function names (more aggressive, allow partial)
        for func in &self.forbidden_functions {
            let re = regex::Regex::new(&format!(r"(?i){}", regex::escape(func))).unwrap();
            if re.is_match(&cleaned) {
                cleaned = re.replace_all(&cleaned, "[REDACTED]").to_string();
                removed = true;
            }
        }

        // Remove ghost patterns
        for re in &self.ghost_patterns {
            if re.is_match(&cleaned) {
                cleaned = re.replace_all(&cleaned, "[REDACTED]").to_string();
                removed = true;
            }
        }

        (cleaned, removed)
    }

    /// Tag new blacklisted items discovered during analysis.
    /// (This would be called by a learning module; we include it for completeness.)
    pub fn tag_new_item(&mut self, item: &str, similarity_to_existing: &[String]) {
        // In production this would log the new item and perhaps add it after manual review.
        eprintln!(
            "⚠️  New blacklist candidate: '{}' (similar to {:?})",
            item, similarity_to_existing
        );
        // For this implementation we do not auto-add; we just report.
    }
}

// ============================================================================
//  TRAIT Governance – now with blacklist enforcement
// ============================================================================

/// A reversible consent trait bound to measurable biophysical limits.
#[derive(Clone, Debug)]
pub struct Trait {
    pub id: TraitId,
    pub host_id: HostId,
    pub domain: EvolutionDomainId,
    pub consent_shard: DemonstratedConsentShard, // see below
    pub reversible: bool,                        // must be true
    pub smart_limit: f32,                        // must be ≤ SMART capacity
    pub active: bool,
    pub dormant_reason: Option<String>,
}

/// Minimal representation of a consent shard (simplified).
#[derive(Clone, Debug)]
pub struct DemonstratedConsentShard {
    pub timestamp: u64,
    pub host_signature: Vec<u8>,
    pub comfort_corridor: (f32, f32), // min, max for pain/irritation
    pub revoked: bool,
}

/// The main governance structure that enforces TRAIT rules plus blacklist.
pub struct TraitGovernance {
    blacklist: Arc<Blacklist>,
    traits: Vec<Trait>,
    safety_policy: EvolutionSafetyPolicy,
}

impl TraitGovernance {
    pub fn new(safety_policy: EvolutionSafetyPolicy) -> Self {
        Self {
            blacklist: Arc::new(Blacklist::new()),
            traits: Vec::new(),
            safety_policy,
        }
    }

    /// Propose a new TRAIT – fails if it violates any blacklist or doctrine.
    pub fn propose_trait(
        &mut self,
        host_id: HostId,
        domain: EvolutionDomainId,
        consent_shard: DemonstratedConsentShard,
        smart_limit: f32,
        reversible: bool,
    ) -> Result<TraitId, GovernanceError> {
        // 1. Check reversible flag – must be true per doctrine
        if !reversible {
            return Err(GovernanceError::IrreversibleTrait);
        }

        // 2. Blacklist check on domain name and consent details
        let domain_str = format!("{:?}", domain);
        if self.blacklist.contains_blacklisted(&domain_str) {
            return Err(GovernanceError::BlacklistedTerm(domain_str));
        }
        if self.blacklist.contains_blacklisted(&format!("{:?}", consent_shard)) {
            return Err(GovernanceError::BlacklistedTerm("consent_shard".into()));
        }

        // 3. Ensure smart_limit is within BRAIN/SCALE bounds
        let max_allowed = self.safety_policy.max_smart_fraction(); // hypothetical
        if smart_limit > max_allowed {
            return Err(GovernanceError::ExceedsSmartCapacity);
        }

        // 4. Ensure the domain is allowed by safety policy (temporary, not structural)
        if !self.safety_policy.allowed_domains.contains(&domain) {
            return Err(GovernanceError::DomainNotAllowed(domain));
        }

        // 5. Check that the trait does not encode any blacklisted function
        //    (e.g., if domain is "rollback", we reject)
        if self.blacklist.contains_blacklisted(&domain_str) {
            return Err(GovernanceError::BlacklistedTerm(domain_str));
        }

        let id = TraitId::new();
        self.traits.push(Trait {
            id,
            host_id,
            domain,
            consent_shard,
            reversible: true,
            smart_limit,
            active: true,
            dormant_reason: None,
        });
        Ok(id)
    }

    /// Revoke consent – marks the trait dormant without deleting it.
    pub fn revoke_consent(&mut self, trait_id: TraitId, reason: &str) -> Result<(), GovernanceError> {
        let t = self.traits.iter_mut().find(|t| t.id == trait_id)
            .ok_or(GovernanceError::TraitNotFound)?;
        if !t.reversible {
            return Err(GovernanceError::IrreversibleTrait);
        }
        t.active = false;
        t.dormant_reason = Some(reason.to_string());
        Ok(())
    }

    /// Re‑activate a dormant trait only if consent is re‑affirmed.
    pub fn reactivate_trait(&mut self, trait_id: TraitId, new_consent: DemonstratedConsentShard) -> Result<(), GovernanceError> {
        let t = self.traits.iter_mut().find(|t| t.id == trait_id)
            .ok_or(GovernanceError::TraitNotFound)?;
        if !t.reversible {
            return Err(GovernanceError::IrreversibleTrait);
        }
        if new_consent.revoked {
            return Err(GovernanceError::ConsentRevoked);
        }
        // Re‑run blacklist check on the domain (in case new blacklist entries exist)
        let domain_str = format!("{:?}", t.domain);
        if self.blacklist.contains_blacklisted(&domain_str) {
            return Err(GovernanceError::BlacklistedTerm(domain_str));
        }
        t.active = true;
        t.dormant_reason = None;
        t.consent_shard = new_consent;
        Ok(())
    }

    /// Apply a mutation step – ensures no blacklisted function is called.
    pub fn apply_mutation(
        &self,
        trait_id: TraitId,
        mutation_function: &str,
    ) -> Result<(), GovernanceError> {
        let t = self.traits.iter().find(|t| t.id == trait_id)
            .ok_or(GovernanceError::TraitNotFound)?;
        if !t.active {
            return Err(GovernanceError::TraitDormant);
        }
        if self.blacklist.contains_blacklisted(mutation_function) {
            return Err(GovernanceError::BlacklistedFunction(mutation_function.into()));
        }
        // Additional biophysical checks would go here...
        Ok(())
    }

    /// Blacklist‑mode: extra hardening – also checks that no new term
    /// slipped through during processing.
    pub fn sanitize_input(&self, user_input: &str) -> (String, bool) {
        self.blacklist.sanitize(user_input)
    }

    /// Discover new blacklisted items by analysing logs.
    /// (Placeholder for the continuous learning required by your rules.)
    pub fn discover_new_threats(&self, logs: &[String]) -> Vec<String> {
        let mut candidates = Vec::new();
        for line in logs {
            // Very simple detection: look for patterns that resemble ghost access
            if line.contains("ghost") && line.contains("access") && !self.blacklist.contains_blacklisted(line) {
                candidates.push(line.clone());
            }
            if line.contains("silent") && line.contains("takeover") {
                candidates.push(line.clone());
            }
        }
        candidates
    }
}

// ============================================================================
//  Error types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error("Trait must be reversible")]
    IrreversibleTrait,
    #[error("Blacklisted term: {0}")]
    BlacklistedTerm(String),
    #[error("Blacklisted function: {0}")]
    BlacklistedFunction(String),
    #[error("Exceeds SMART capacity")]
    ExceedsSmartCapacity,
    #[error("Domain not allowed: {0:?}")]
    DomainNotAllowed(EvolutionDomainId),
    #[error("Trait not found")]
    TraitNotFound,
    #[error("Consent revoked")]
    ConsentRevoked,
    #[error("Trait is dormant")]
    TraitDormant,
}

// ============================================================================
//  Example usage (tests)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EvolutionDomainId;

    #[test]
    fn test_blacklist_sanitization() {
        let bl = Blacklist::new();
        let input = "We should use a rollback function to revert changes.";
        let (cleaned, removed) = bl.sanitize(input);
        assert!(removed);
        assert!(!cleaned.contains("rollback"));
        println!("Cleaned: {}", cleaned);
    }

    #[test]
    fn test_trait_proposal_rejects_blacklisted() {
        let policy = EvolutionSafetyPolicy {
            allowed_domains: vec![EvolutionDomainId::new("safe_domain")],
            max_smart_fraction: 0.5,
            ..Default::default()
        };
        let mut gov = TraitGovernance::new(policy);
        let consent = DemonstratedConsentShard {
            timestamp: 123,
            host_signature: vec![1, 2, 3],
            comfort_corridor: (0.0, 10.0),
            revoked: false,
        };
        let domain = EvolutionDomainId::new("rollback"); // blacklisted
        let res = gov.propose_trait(
            HostId::new(1),
            domain,
            consent,
            0.3,
            true,
        );
        assert!(matches!(res, Err(GovernanceError::BlacklistedTerm(_))));
    }

    #[test]
    fn test_consent_revocation() {
        let policy = EvolutionSafetyPolicy::default();
        let mut gov = TraitGovernance::new(policy);
        let consent = DemonstratedConsentShard::default();
        let id = gov.propose_trait(HostId::new(1), EvolutionDomainId::new("test"), consent, 0.2, true).unwrap();
        gov.revoke_consent(id, "pain threshold exceeded").unwrap();
        let t = gov.traits.iter().find(|t| t.id == id).unwrap();
        assert!(!t.active);
        assert_eq!(t.dormant_reason, Some("pain threshold exceeded".into()));
    }
}
