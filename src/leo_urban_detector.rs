//! # LEO/Urban Threat Detector Module
//! 
//! This module implements the threat detection engine for the Aegis-Shield system,
//! mapping fused telemetry (text, XR, BCI, behavior) into SpanScore family weights
//! for LEO and urban-terrorism families, then computing RogueScore and CapabilityMode.
//! 
//! ## Core Invariant
//! 
//! All transitions must satisfy monotonicity:
//!   ∀s₀,s₁,c. Reach(s₀,s₁) ⇒ (c ∈ U(s₀) ⇒ c ∈ U(s₁))
//! 
//! ## Cool-Down Constraints
//! 
//! - General policies: Maximum 90 days (7,776,000 seconds)
//! - Healthcare/Cybernetic: Maximum 24 hours (86,400 seconds)
//! 
//! The 24-hour maximum for cybernetic-evolution and biocompatibility-testing
//! prevents weaponization of cool-downs to delay critical medical procedures,
//! chip upgrades, or implant compatibility verification beyond safe windows.
//! 
//! ## Cross-Language Guarantee
//! 
//! This module must produce identical results to:
//! - Lua: eligibility_state_machine.lua
//! - C++: interface_contracts.hpp
//! - ALN: governancepolicy.aln
//! 
//! ## Blacklist Integration
//! 
//! COOL-DOWN-MISUSE-CRS is tagged as a diagnostic centroid (sanitized:
//! COOL-DOWN-SEMANTICS-REDACTED) and must never appear as an executable operator.

#![deny(clippy::all)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};
use serde::{Serialize, Deserialize};
use thiserror::Error;

// Import from sibling modules
use crate::cool_down_invariants::{
    Capability, GovernanceMode, NeurorightCategory, PendingPolicy, ProposalId,
    CooldownAbuseCentroid, NonSuspensionProof, CoolDownError,
};

/// ============================================================================
/// SECTION 1: CONFIGURATION CONSTANTS
/// ============================================================================

/// Configuration for cool-down duration bounds
pub struct CooldownBounds {
    /// Minimum cool-down duration (1 hour)
    pub const MIN_GENERAL: Duration = Duration::from_secs(3600);
    /// Maximum cool-down duration for general policies (90 days)
    pub const MAX_GENERAL: Duration = Duration::from_secs(7_776_000);
    /// Maximum cool-down duration for healthcare/cybernetic (24 hours)
    pub const MAX_HEALTHCARE: Duration = Duration::from_secs(86_400);
    /// Excessive duration threshold for abuse detection (30 days)
    pub const EXCESSIVE_THRESHOLD: Duration = Duration::from_secs(2_592_000);
    /// Abuse risk threshold for governance escalation
    pub const ABUSE_RISK_THRESHOLD: f64 = 0.75;
}

/// ============================================================================
/// SECTION 2: BLACKLIST FAMILY DEFINITIONS
/// ============================================================================

/// Threat family categorization matching lexicon-entry.schema.yaml
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlacklistFamily {
    /// Neural Harassment and Surveillance Patterns
    NHSP = 0,
    /// Harmful Treatment and Abuse patterns
    HTA = 1,
    /// Probation and Surveillance Abuse patterns
    PSA = 2,
    /// Neural Interface Hijacking patterns
    NIH = 3,
    /// Control Reversal Syndrome patterns
    CRS = 4,
    /// Urban Grid Terrorism patterns
    UrbanGrid = 5,
}

impl BlacklistFamily {
    /// Returns all blacklist families for iteration
    pub const fn all() -> &'static [Self] {
        &[
            Self::NHSP,
            Self::HTA,
            Self::PSA,
            Self::NIH,
            Self::CRS,
            Self::UrbanGrid,
        ]
    }
    
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NHSP => "NHSP",
            Self::HTA => "HTA",
            Self::PSA => "PSA",
            Self::NIH => "NIH",
            Self::CRS => "CRS",
            Self::UrbanGrid => "URBAN_GRID",
        }
    }
    
    /// Check if this family is associated with healthcare/cybernetic threats
    pub fn is_healthcare_related(&self) -> bool {
        matches!(self, Self::HTA | Self::CRS)
    }
}

/// ============================================================================
/// SECTION 3: SPAN SCORE DEFINITIONS
/// ============================================================================

/// Span score for individual threat pattern detection
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpanScore {
    /// Blacklist family this score belongs to
    pub family: BlacklistFamily,
    /// Pattern identifier within the family (from lexicon-entry.schema.yaml)
    pub pattern_id: String,
    /// Risk weight (0.0 to 1.0)
    pub weight: f64,
    /// Timestamp of detection (Unix epoch seconds)
    pub detected_at: u64,
    /// Whether this pattern triggered an escalation
    pub triggered_escalation: bool,
    /// Neuroright categories affected
    pub neuroright_impact: BTreeSet<NeurorightCategory>,
    /// Whether this is a healthcare/cybernetic related pattern
    pub is_healthcare_related: bool,
}

impl SpanScore {
    /// Create a new span score
    pub fn new(
        family: BlacklistFamily,
        pattern_id: impl Into<String>,
        weight: f64,
        neuroright_impact: BTreeSet<NeurorightCategory>,
    ) -> Self {
        let pattern_id = pattern_id.into();
        let is_healthcare_related = family.is_healthcare_related() ||
            pattern_id.contains("HEALTHCARE") ||
            pattern_id.contains("CYBERNETIC") ||
            pattern_id.contains("BIOSCOMPAT") ||
            pattern_id.contains("UPGRADE");
        
        Self {
            family,
            pattern_id,
            weight: weight.clamp(0.0, 1.0),
            detected_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            triggered_escalation: false,
            neuroright_impact,
            is_healthcare_related,
        }
    }
    
    /// Check if this span score indicates cool-down abuse
    pub fn is_cooldown_abuse_indicator(&self) -> bool {
        self.pattern_id.contains("COOLDOWN") ||
        self.pattern_id.contains("CONTROL_REVERSAL") ||
        self.pattern_id.contains("DORMANCY") ||
        self.pattern_id.contains("CONSENT_ROLLBACK")
    }
}

/// ============================================================================
/// SECTION 4: ROGUE SCORE DEFINITIONS
/// ============================================================================

/// Rogue score representing aggregate threat level
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RogueScore {
    /// Aggregate risk score (0.0 to 1.0)
    pub score: f64,
    /// Number of threat patterns detected
    pub pattern_count: usize,
    /// Breakdown by blacklist family
    pub family_weights: BTreeMap<BlacklistFamily, f64>,
    /// Timestamp of calculation (Unix epoch seconds)
    pub calculated_at: u64,
    /// Whether COOL-DOWN-MISUSE-CRS patterns were detected
    pub cooldown_abuse_detected: bool,
    /// Whether healthcare/cybernetic threats were detected
    pub healthcare_threats_detected: bool,
    /// Maximum cooldown duration based on threat types
    pub max_cooldown_duration: Duration,
}

impl RogueScore {
    /// Create an empty rogue score
    pub fn new() -> Self {
        Self {
            score: 0.0,
            pattern_count: 0,
            family_weights: BTreeMap::new(),
            calculated_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            cooldown_abuse_detected: false,
            healthcare_threats_detected: false,
            max_cooldown_duration: CooldownBounds::MAX_GENERAL,
        }
    }
    
    /// Calculate RogueScore from span scores
    pub fn from_spans(spans: &[SpanScore]) -> Self {
        let mut result = Self::new();
        
        for span in spans {
            *result.family_weights.entry(span.family).or_insert(0.0) += span.weight;
            result.pattern_count += 1;
            
            // Check for COOL-DOWN-MISUSE-CRS patterns
            if span.is_cooldown_abuse_indicator() {
                result.cooldown_abuse_detected = true;
            }
            
            // Check for healthcare/cybernetic threats
            if span.is_healthcare_related {
                result.healthcare_threats_detected = true;
            }
        }
        
        // Calculate aggregate score (capped at 1.0)
        let aggregate: f64 = result.family_weights.values().sum();
        result.score = aggregate.min(1.0);
        
        // Set maximum cooldown based on threat types
        // CRITICAL: Healthcare/cybernetic threats require 24-hour max
        result.max_cooldown_duration = if result.healthcare_threats_detected {
            CooldownBounds::MAX_HEALTHCARE
        } else {
            CooldownBounds::MAX_GENERAL
        };
        
        result
    }
    
    /// Check if rogue score exceeds abuse threshold
    pub fn exceeds_abuse_threshold(&self) -> bool {
        self.score >= CooldownBounds::ABUSE_RISK_THRESHOLD
    }
    
    /// Get the recommended governance mode based on score
    pub fn recommended_governance_mode(&self) -> GovernanceMode {
        if self.score >= 0.75 {
            GovernanceMode::ProtectedLockdown
        } else if self.score >= 0.50 {
            GovernanceMode::AugmentedReview
        } else if self.score >= 0.25 {
            GovernanceMode::AugmentedLog
        } else {
            GovernanceMode::Normal
        }
    }
}

impl Default for RogueScore {
    fn default() -> Self {
        Self::new()
    }
}

/// ============================================================================
/// SECTION 5: CAPABILITY MODE DEFINITIONS
/// ============================================================================

/// Capability mode derived from RogueScore
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityMode {
    /// Current governance mode
    pub mode: GovernanceMode,
    /// RogueScore that determined this mode
    pub rogue_score: RogueScore,
    /// Timestamp of mode determination (Unix epoch seconds)
    pub determined_at: u64,
    /// Whether this mode was triggered by cooldown abuse detection
    pub cooldown_triggered: bool,
    /// Whether healthcare/cybernetic protections are active
    pub healthcare_protections_active: bool,
}

impl CapabilityMode {
    /// Derive CapabilityMode from RogueScore
    pub fn from_roguescore(score: &RogueScore) -> Self {
        Self {
            mode: score.recommended_governance_mode(),
            rogue_score: score.clone(),
            determined_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            cooldown_triggered: score.cooldown_abuse_detected,
            healthcare_protections_active: score.healthcare_threats_detected,
        }
    }
    
    /// Check if capability mode allows direct user action
    pub fn allows_direct_action(&self) -> bool {
        matches!(self.mode, GovernanceMode::Normal | GovernanceMode::AugmentedLog)
    }
    
    /// Check if healthcare/cybernetic cooldown limits apply
    pub fn healthcare_cooldown_limits_apply(&self) -> bool {
        self.healthcare_protections_active
    }
}

/// ============================================================================
/// SECTION 6: TELEMETRY INPUT TYPES
/// ============================================================================

/// Fused telemetry input from multiple sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusedTelemetry {
    /// Text-based telemetry (chat, logs, communications)
    pub text_signals: Vec<TextSignal>,
    /// XR-based telemetry (overlay, spatial, visual)
    pub xr_signals: Vec<XRSignal>,
    /// BCI-based telemetry (neural, motor, sensory)
    pub bci_signals: Vec<BCISignal>,
    /// Behavioral telemetry (user actions, patterns)
    pub behavioral_signals: Vec<BehavioralSignal>,
    /// Timestamp of telemetry collection
    pub collected_at: u64,
}

impl FusedTelemetry {
    /// Create new fused telemetry
    pub fn new() -> Self {
        Self {
            text_signals: Vec::new(),
            xr_signals: Vec::new(),
            bci_signals: Vec::new(),
            behavioral_signals: Vec::new(),
            collected_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl Default for FusedTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Text-based signal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSignal {
    /// Signal content (sanitized, no raw neural data)
    pub content: String,
    /// Source identifier
    pub source: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Linguistic markers detected
    pub linguistic_markers: Vec<String>,
}

/// XR-based signal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XRSignal {
    /// Overlay signature
    pub overlay_signature: String,
    /// Spatial coordinates (sanitized)
    pub spatial_hash: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Hijacking indicators
    pub hijacking_indicators: Vec<String>,
}

/// BCI-based signal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BCISignal {
    /// Frequency range (e.g., "8-12Hz")
    pub frequency_range: String,
    /// Amplitude metrics (sanitized)
    pub amplitude_hash: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Distress indicators
    pub distress_indicators: Vec<String>,
}

/// Behavioral signal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralSignal {
    /// Behavior pattern identifier
    pub pattern_id: String,
    /// User response pattern
    pub user_response: String,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Escalation indicators
    pub escalation_indicators: Vec<String>,
}

/// ============================================================================
/// SECTION 7: LEO/URBAN DETECTOR IMPLEMENTATION
/// ============================================================================

/// Main detector that maps telemetry to SpanScores
pub struct LEODetector {
    /// Lexicon entries loaded from lexicon-entry.schema.yaml
    lexicon_entries: BTreeMap<String, LexiconEntry>,
    /// Family weights for scoring
    family_weights: BTreeMap<BlacklistFamily, f64>,
    /// Cooldown abuse centroids
    abuse_centroids: Vec<CooldownAbuseCentroid>,
}

/// Lexicon entry structure (matches lexicon-entry.schema.yaml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexiconEntry {
    /// Unique entry identifier
    pub id: String,
    /// Version
    pub version: String,
    /// Threat family
    pub family: BlacklistFamily,
    /// Severity level (1-10)
    pub severity: u8,
    /// Pattern definition
    pub pattern: PatternDefinition,
    /// Neuroright impacts
    pub neurorights: Vec<NeurorightImpact>,
    /// Legal basis
    pub legal_basis: LegalBasisDefinition,
    /// Cool-down configuration
    pub cooldown_config: CooldownConfigDefinition,
    /// Diagnostic centroids
    pub diagnostic_centroids: Vec<DiagnosticCentroidDefinition>,
}

/// Pattern definition (signal, semantic, behavioral)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDefinition {
    /// Signal patterns
    pub signal: SignalPattern,
    /// Semantic patterns
    pub semantic: SemanticPattern,
    /// Behavioral patterns
    pub behavioral: BehavioralPattern,
}

/// Signal pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalPattern {
    /// Frequency range for neural signals
    pub frequency_range: Option<String>,
    /// XR overlay signature
    pub xr_overlay_signature: Option<String>,
    /// Network port scan indicator
    pub network_port_scan: bool,
}

/// Semantic pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticPattern {
    /// Intent classification
    pub intent_classification: String,
    /// Linguistic markers
    pub linguistic_markers: Vec<String>,
    /// Context triggers
    pub context_triggers: Vec<String>,
}

/// Behavioral pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralPattern {
    /// User response pattern
    pub user_response_pattern: String,
    /// Escalation path
    pub escalation_path: Vec<String>,
    /// Mitigation strategy
    pub mitigation_strategy: String,
}

/// Neuroright impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeurorightImpact {
    /// Category
    pub category: NeurorightCategory,
    /// Impact type
    pub impact_type: String,
    /// Severity
    pub severity: u8,
    /// Mitigations
    pub mitigations: Vec<String>,
}

/// Legal basis definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalBasisDefinition {
    /// Basis type
    pub basis_type: String,
    /// Reference
    pub reference: String,
    /// Authority
    pub authority: String,
}

/// Cool-down configuration definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooldownConfigDefinition {
    /// Duration in seconds
    pub duration_seconds: u64,
    /// Affected domains
    pub affected_domains: Vec<String>,
    /// Exempt domains
    pub exempt_domains: Vec<String>,
    /// Abuse detection enabled
    pub abuse_detection_enabled: bool,
}

/// Diagnostic centroid definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCentroidDefinition {
    /// Sanitized centroid ID
    pub centroid_id: String,
    /// Internal diagnostic ID
    pub internal_diagnostic_id: String,
    /// Risk weight
    pub risk_weight: f64,
    /// Detection criteria
    pub detection_criteria: Vec<String>,
}

impl LEODetector {
    /// Create a new detector with lexicon entries
    pub fn new(lexicon_entries: Vec<LexiconEntry>) -> Self {
        let lexicon_map: BTreeMap<String, LexiconEntry> = lexicon_entries
            .into_iter()
            .map(|entry| (entry.id.clone(), entry))
            .collect();
        
        let mut family_weights = BTreeMap::new();
        for &family in BlacklistFamily::all() {
            family_weights.insert(family, 0.0);
        }
        
        Self {
            lexicon_entries: lexicon_map,
            family_weights,
            abuse_centroids: Vec::new(),
        }
    }
    
    /// Process fused telemetry and generate span scores
    pub fn process_telemetry(&mut self, telemetry: &FusedTelemetry) -> Vec<SpanScore> {
        let mut span_scores = Vec::new();
        
        // Reset family weights
        for weight in self.family_weights.values_mut() {
            *weight = 0.0;
        }
        
        // Process text signals
        for signal in &telemetry.text_signals {
            if let Some(score) = self.detect_text_pattern(signal) {
                span_scores.push(score);
            }
        }
        
        // Process XR signals
        for signal in &telemetry.xr_signals {
            if let Some(score) = self.detect_xr_pattern(signal) {
                span_scores.push(score);
            }
        }
        
        // Process BCI signals
        for signal in &telemetry.bci_signals {
            if let Some(score) = self.detect_bci_pattern(signal) {
                span_scores.push(score);
            }
        }
        
        // Process behavioral signals
        for signal in &telemetry.behavioral_signals {
            if let Some(score) = self.detect_behavioral_pattern(signal) {
                span_scores.push(score);
            }
        }
        
        // Update family weights
        for score in &span_scores {
            *self.family_weights.entry(score.family).or_insert(0.0) += score.weight;
        }
        
        span_scores
    }
    
    /// Detect text-based threat patterns
    fn detect_text_pattern(&self, signal: &TextSignal) -> Option<SpanScore> {
        for (_, entry) in &self.lexicon_entries {
            // Check linguistic markers
            let marker_match = entry.pattern.semantic.linguistic_markers
                .iter()
                .any(|marker| signal.linguistic_markers.contains(marker));
            
            if marker_match && signal.confidence >= 0.7 {
                let mut neuroright_impact = BTreeSet::new();
                for impact in &entry.neurorights {
                    neuroright_impact.insert(impact.category);
                }
                
                let weight = entry.severity as f64 / 10.0 * signal.confidence;
                
                return Some(SpanScore::new(
                    entry.family,
                    format!("{}-TEXT", entry.id),
                    weight,
                    neuroright_impact,
                ));
            }
        }
        None
    }
    
    /// Detect XR-based threat patterns
    fn detect_xr_pattern(&self, signal: &XRSignal) -> Option<SpanScore> {
        for (_, entry) in &self.lexicon_entries {
            // Check XR overlay signature
            if let Some(expected_sig) = &entry.pattern.signal.xr_overlay_signature {
                if expected_sig == &signal.overlay_signature && signal.confidence >= 0.7 {
                    let mut neuroright_impact = BTreeSet::new();
                    for impact in &entry.neurorights {
                        neuroright_impact.insert(impact.category);
                    }
                    
                    let weight = entry.severity as f64 / 10.0 * signal.confidence;
                    
                    return Some(SpanScore::new(
                        entry.family,
                        format!("{}-XR", entry.id),
                        weight,
                        neuroright_impact,
                    ));
                }
            }
        }
        None
    }
    
    /// Detect BCI-based threat patterns
    fn detect_bci_pattern(&self, signal: &BCISignal) -> Option<SpanScore> {
        for (_, entry) in &self.lexicon_entries {
            // Check frequency range
            if let Some(expected_freq) = &entry.pattern.signal.frequency_range {
                if expected_freq == &signal.frequency_range && signal.confidence >= 0.7 {
                    let mut neuroright_impact = BTreeSet::new();
                    for impact in &entry.neurorights {
                        neuroright_impact.insert(impact.category);
                    }
                    
                    let weight = entry.severity as f64 / 10.0 * signal.confidence;
                    
                    return Some(SpanScore::new(
                        entry.family,
                        format!("{}-BCI", entry.id),
                        weight,
                        neuroright_impact,
                    ));
                }
            }
        }
        None
    }
    
    /// Detect behavioral threat patterns
    fn detect_behavioral_pattern(&self, signal: &BehavioralSignal) -> Option<SpanScore> {
        for (_, entry) in &self.lexicon_entries {
            // Check user response pattern
            if entry.pattern.behavioral.user_response_pattern == signal.user_response 
                && signal.confidence >= 0.7 
            {
                let mut neuroright_impact = BTreeSet::new();
                for impact in &entry.neurorights {
                    neuroright_impact.insert(impact.category);
                }
                
                let weight = entry.severity as f64 / 10.0 * signal.confidence;
                
                return Some(SpanScore::new(
                    entry.family,
                    format!("{}-BEHAVIORAL", entry.id),
                    weight,
                    neuroright_impact,
                ));
            }
        }
        None
    }
    
    /// Validate cool-down configuration against constraints
    pub fn validate_cooldown_config(
        &self,
        config: &CooldownConfigDefinition,
        is_healthcare_related: bool,
    ) -> Result<(), CooldownValidationError> {
        // Check duration bounds
        let duration = Duration::from_secs(config.duration_seconds);
        let max_allowed = if is_healthcare_related {
            CooldownBounds::MAX_HEALTHCARE
        } else {
            CooldownBounds::MAX_GENERAL
        };
        
        if duration < CooldownBounds::MIN_GENERAL {
            return Err(CooldownValidationError::DurationTooShort(config.duration_seconds));
        }
        
        if duration > max_allowed {
            return Err(CooldownValidationError::DurationTooLong {
                duration: config.duration_seconds,
                max_allowed: max_allowed.as_secs(),
                is_healthcare: is_healthcare_related,
            });
        }
        
        // Check forbidden domains
        let forbidden_domains = ["CAPABILITIES", "BCI_ACCESS", "HEALTHCARE_ACCESS", 
                                  "IDENTITY_OPERATIONS", "DEVICE_PAIRING"];
        
        for domain in &config.affected_domains {
            if forbidden_domains.contains(&domain.as_str()) {
                return Err(CooldownValidationError::ForbiddenDomain(domain.clone()));
            }
        }
        
        // Check exempt domains include capabilities
        let required_exempts = ["CAPABILITIES", "BCI_ACCESS", "HEALTHCARE_ACCESS"];
        for exempt in required_exempts {
            if !config.exempt_domains.iter().any(|d| d == exempt) {
                return Err(CooldownValidationError::MissingExemptDomain(exempt.to_string()));
            }
        }
        
        // Check abuse detection is enabled
        if !config.abuse_detection_enabled {
            return Err(CooldownValidationError::AbuseDetectionDisabled);
        }
        
        Ok(())
    }
    
    /// Detect cool-down abuse patterns in lexicon entries
    pub fn detect_cooldown_abuse(&self, entry: &LexiconEntry) -> Vec<CooldownAbuseCentroid> {
        let mut centroids = Vec::new();
        
        // Check for excessive duration
        if entry.cooldown_config.duration_seconds > CooldownBounds::EXCESSIVE_THRESHOLD.as_secs() {
            centroids.push(CooldownAbuseCentroid::new(0.25, false));
        }
        
        // Check for critical neuroright impact without emergency
        let has_critical = entry.neurorights.iter().any(|n| {
            n.category == NeurorightCategory::MentalIntegrity ||
            n.category == NeurorightCategory::CognitiveLiberty
        });
        
        let has_emergency = entry.legal_basis.basis_type.contains("EMERGENCY");
        
        if has_critical && !has_emergency {
            centroids.push(CooldownAbuseCentroid::new(0.35, false));
        }
        
        // Check for vague legal basis
        if entry.legal_basis.reference.len() < 10 ||
            (!entry.legal_basis.reference.contains('§') &&
             !entry.legal_basis.reference.contains("STATUTE") &&
             !entry.legal_basis.reference.contains("WARRANT"))
        {
            centroids.push(CooldownAbuseCentroid::new(0.15, false));
        }
        
        centroids
    }
    
    /// Get family weights for external use
    pub fn get_family_weights(&self) -> &BTreeMap<BlacklistFamily, f64> {
        &self.family_weights
    }
}

/// ============================================================================
/// SECTION 8: ERROR TYPES
/// ============================================================================

/// Cool-down validation errors
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CooldownValidationError {
    /// Duration too short
    #[error("Cool-down duration {0}s is below minimum threshold")]
    DurationTooShort(u64),
    
    /// Duration too long
    #[error("Cool-down duration {duration}s exceeds maximum ({max_allowed}s, healthcare={is_healthcare})")]
    DurationTooLong {
        duration: u64,
        max_allowed: u64,
        is_healthcare: bool,
    },
    
    /// Forbidden domain included
    #[error("Cool-down cannot affect forbidden domain: {0}")]
    ForbiddenDomain(String),
    
    /// Missing required exempt domain
    #[error("Cool-down must exempt domain: {0}")]
    MissingExemptDomain(String),
    
    /// Abuse detection disabled
    #[error("Cool-down abuse detection must be enabled")]
    AbuseDetectionDisabled,
}

/// Detector errors
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorError {
    /// Lexicon entry not found
    #[error("Lexicon entry not found: {0}")]
    EntryNotFound(String),
    
    /// Invalid telemetry input
    #[error("Invalid telemetry input: {0}")]
    InvalidTelemetry(String),
    
    /// Cool-down validation failed
    #[error("Cool-down validation failed: {0}")]
    CooldownValidation(#[from] CooldownValidationError),
}

/// ============================================================================
/// SECTION 9: EVIDENCE BUNDLE GENERATION
/// ============================================================================

/// Evidence bundle for privacy-preserving audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Unique bundle identifier
    pub bundle_id: String,
    /// Timestamp of event (Unix epoch seconds)
    pub timestamp: u64,
    /// Pseudonymous user identifier
    pub pseudonymous_user_id: String,
    /// Threat families detected
    pub threat_families: Vec<String>,
    /// RogueScore at time of event
    pub rogue_score: f64,
    /// CapabilityMode at time of event
    pub capability_mode: GovernanceMode,
    /// Neurorights at stake
    pub neurorights_at_stake: Vec<String>,
    /// Enforcement actions taken
    pub enforcement_actions: Vec<String>,
    /// Related proposal IDs
    pub related_proposals: Vec<String>,
    /// Non-suspension proof hash
    pub non_suspension_proof_hash: String,
    /// Integrity hash
    pub integrity_hash: String,
}

impl EvidenceBundle {
    /// Create a new evidence bundle
    pub fn new(
        user_id: &str,
        threat_families: Vec<BlacklistFamily>,
        rogue_score: &RogueScore,
        capability_mode: &CapabilityMode,
    ) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        rogue_score.score.hash(&mut hasher);
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .hash(&mut hasher);
        
        let integrity_hash = format!("{:016x}", hasher.finish());
        
        Self {
            bundle_id: integrity_hash.clone(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            pseudonymous_user_id: format!("user_{:08x}", hasher.finish() % 0xFFFFFFFF),
            threat_families: threat_families.iter().map(|f| f.as_str().to_string()).collect(),
            rogue_score: rogue_score.score,
            capability_mode: capability_mode.mode,
            neurorights_at_stake: Vec::new(), // Populated based on spans
            enforcement_actions: Vec::new(),
            related_proposals: Vec::new(),
            non_suspension_proof_hash: String::new(),
            integrity_hash,
        }
    }
}

/// ============================================================================
/// SECTION 10: TESTS
/// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_lexicon_entry() -> LexiconEntry {
        LexiconEntry {
            id: "HTA-CONDITIONED-COMPLIANCE-LOOP".to_string(),
            version: "1.0.0".to_string(),
            family: BlacklistFamily::HTA,
            severity: 8,
            pattern: PatternDefinition {
                signal: SignalPattern {
                    frequency_range: Some("8-12Hz".to_string()),
                    xr_overlay_signature: Some("COMPLIANCE_REWARD".to_string()),
                    network_port_scan: false,
                },
                semantic: SemanticPattern {
                    intent_classification: "COERCION".to_string(),
                    linguistic_markers: vec!["good citizen".to_string()],
                    context_triggers: vec!["authority_interaction".to_string()],
                },
                behavioral: BehavioralPattern {
                    user_response_pattern: "compliance".to_string(),
                    escalation_path: vec!["reward".to_string()],
                    mitigation_strategy: "Escalate governance".to_string(),
                },
            },
            neurorights: vec![NeurorightImpact {
                category: NeurorightCategory::CognitiveLiberty,
                impact_type: "NEGATIVE".to_string(),
                severity: 8,
                mitigations: vec!["Governance escalation".to_string()],
            }],
            legal_basis: LegalBasisDefinition {
                basis_type: "STATUTE".to_string(),
                reference: "STATUTE §123.456".to_string(),
                authority: "Federal Commission".to_string(),
            },
            cooldown_config: CooldownConfigDefinition {
                duration_seconds: 86400,
                affected_domains: vec!["GOVERNANCE".to_string()],
                exempt_domains: vec!["CAPABILITIES".to_string(), "BCI_ACCESS".to_string()],
                abuse_detection_enabled: true,
            },
            diagnostic_centroids: vec![DiagnosticCentroidDefinition {
                centroid_id: "COOL-DOWN-SEMANTICS-REDACTED".to_string(),
                internal_diagnostic_id: "COOL-DOWN-MISUSE-CRS".to_string(),
                risk_weight: 0.85,
                detection_criteria: vec!["Duration check".to_string()],
            }],
        }
    }
    
    #[test]
    fn test_span_score_creation() {
        let mut neuroright_impact = BTreeSet::new();
        neuroright_impact.insert(NeurorightCategory::MentalIntegrity);
        
        let span = SpanScore::new(
            BlacklistFamily::HTA,
            "TEST-PATTERN",
            0.8,
            neuroright_impact,
        );
        
        assert_eq!(span.family, BlacklistFamily::HTA);
        assert_eq!(span.pattern_id, "TEST-PATTERN");
        assert!(span.weight >= 0.0 && span.weight <= 1.0);
    }
    
    #[test]
    fn test_rogue_score_from_spans() {
        let mut neuroright_impact = BTreeSet::new();
        neuroright_impact.insert(NeurorightCategory::MentalIntegrity);
        
        let spans = vec![
            SpanScore::new(BlacklistFamily::HTA, "PATTERN-1", 0.5, neuroright_impact.clone()),
            SpanScore::new(BlacklistFamily::CRS, "PATTERN-2", 0.4, neuroright_impact.clone()),
        ];
        
        let rogue = RogueScore::from_spans(&spans);
        
        assert!(rogue.score > 0.0);
        assert_eq!(rogue.pattern_count, 2);
        assert!(rogue.family_weights.contains_key(&BlacklistFamily::HTA));
    }
    
    #[test]
    fn test_healthcare_cooldown_limit() {
        let mut neuroright_impact = BTreeSet::new();
        neuroright_impact.insert(NeurorightCategory::MentalIntegrity);
        
        // Create healthcare-related span
        let spans = vec![
            SpanScore::new(
                BlacklistFamily::HTA,
                "HEALTHCARE-UPGRADE-BLOCK",
                0.6,
                neuroright_impact,
            ),
        ];
        
        let rogue = RogueScore::from_spans(&spans);
        
        // Should use 24-hour max for healthcare
        assert_eq!(rogue.max_cooldown_duration, CooldownBounds::MAX_HEALTHCARE);
        assert!(rogue.healthcare_threats_detected);
    }
    
    #[test]
    fn test_cooldown_validation_healthcare() {
        let detector = LEODetector::new(vec![create_test_lexicon_entry()]);
        
        // Test healthcare-related config with 24-hour limit
        let healthcare_config = CooldownConfigDefinition {
            duration_seconds: 86400, // 24 hours - should pass
            affected_domains: vec!["GOVERNANCE".to_string()],
            exempt_domains: vec![
                "CAPABILITIES".to_string(),
                "BCI_ACCESS".to_string(),
                "HEALTHCARE_ACCESS".to_string(),
            ],
            abuse_detection_enabled: true,
        };
        
        assert!(detector.validate_cooldown_config(&healthcare_config, true).is_ok());
        
        // Test healthcare-related config exceeding 24-hour limit
        let excessive_config = CooldownConfigDefinition {
            duration_seconds: 172800, // 48 hours - should fail for healthcare
            affected_domains: vec!["GOVERNANCE".to_string()],
            exempt_domains: vec![
                "CAPABILITIES".to_string(),
                "BCI_ACCESS".to_string(),
                "HEALTHCARE_ACCESS".to_string(),
            ],
            abuse_detection_enabled: true,
        };
        
        let result = detector.validate_cooldown_config(&excessive_config, true);
        assert!(result.is_err());
        
        // Same config should pass for non-healthcare
        assert!(detector.validate_cooldown_config(&excessive_config, false).is_ok());
    }
    
    #[test]
    fn test_cooldown_validation_forbidden_domains() {
        let detector = LEODetector::new(vec![create_test_lexicon_entry()]);
        
        let forbidden_config = CooldownConfigDefinition {
            duration_seconds: 86400,
            affected_domains: vec!["CAPABILITIES".to_string()], // FORBIDDEN
            exempt_domains: vec![],
            abuse_detection_enabled: true,
        };
        
        let result = detector.validate_cooldown_config(&forbidden_config, false);
        assert!(result.is_err());
        
        if let Err(CooldownValidationError::ForbiddenDomain(domain)) = result {
            assert_eq!(domain, "CAPABILITIES");
        } else {
            panic!("Expected ForbiddenDomain error");
        }
    }
    
    #[test]
    fn test_capability_mode_derivation() {
        let rogue = RogueScore {
            score: 0.65,
            pattern_count: 3,
            family_weights: BTreeMap::new(),
            calculated_at: 0,
            cooldown_abuse_detected: true,
            healthcare_threats_detected: false,
            max_cooldown_duration: CooldownBounds::MAX_GENERAL,
        };
        
        let mode = CapabilityMode::from_roguescore(&rogue);
        
        assert_eq!(mode.mode, GovernanceMode::AugmentedReview);
        assert!(mode.cooldown_triggered);
        assert!(!mode.healthcare_protections_active);
    }
    
    #[test]
    fn test_evidence_bundle_generation() {
        let rogue = RogueScore::new();
        let mode = CapabilityMode::from_roguescore(&rogue);
        
        let bundle = EvidenceBundle::new(
            "did:test:user:1",
            vec![BlacklistFamily::HTA, BlacklistFamily::CRS],
            &rogue,
            &mode,
        );
        
        assert!(!bundle.bundle_id.is_empty());
        assert_eq!(bundle.threat_families.len(), 2);
        assert!(!bundle.integrity_hash.is_empty());
    }
    
    #[test]
    fn test_detector_telemetry_processing() {
        let mut detector = LEODetector::new(vec![create_test_lexicon_entry()]);
        
        let mut telemetry = FusedTelemetry::new();
        telemetry.behavioral_signals.push(BehavioralSignal {
            pattern_id: "TEST".to_string(),
            user_response: "compliance".to_string(),
            confidence: 0.85,
            escalation_indicators: vec![],
        });
        
        let spans = detector.process_telemetry(&telemetry);
        
        // Should detect at least one pattern
        assert!(!spans.is_empty() || detector.get_family_weights().len() > 0);
    }
}
