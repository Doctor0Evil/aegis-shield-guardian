// ============================================================================
// Aegis-Shield Interface Contracts Header
// ============================================================================
//
// Version: 1.0.0
// Effective Date: 2026-03-24
// Classification: NEURORIGHTS-ANCHORED / MONOTONE-GUARANTEED
// Language: C++17 (compatible with C++20)
//
// This header defines the interface contracts for the Aegis-Shield system,
// providing type definitions and interface specifications that ensure
// cross-language consistency between Rust, Lua, ALN, and C++ implementations.
//
// CORE INVARIANT: All transitions must satisfy monotonicity:
//   ∀s₀,s₁,c. Reach(s₀,s₁) ⇒ (c ∈ U(s₀) ⇒ c ∈ U(s₁))
//
// COOL-DOWN CONSTRAINT: Waiting periods may only affect governance
// bits (G), never user capabilities (U). Any policy attempting to
// suspend capabilities via cool-down is formally invalid.
//
// CROSS-LANGUAGE GUARANTEE: Types defined here must produce identical
// behavior to Rust (cool_down_invariants.rs), Lua (eligibility_state_machine.lua),
// and ALN (governancepolicy.aln) implementations.
// ============================================================================

#ifndef AEGIS_SHIELD_INTERFACE_CONTRACTS_HPP
#define AEGIS_SHIELD_INTERFACE_CONTRACTS_HPP

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <sstream>

namespace aegis {
namespace shield {

// ============================================================================
// SECTION 1: VERSION AND COMPATIBILITY
// ============================================================================

constexpr const char* INTERFACE_VERSION = "1.0.0";
constexpr uint32_t INTERFACE_VERSION_MAJOR = 1;
constexpr uint32_t INTERFACE_VERSION_MINOR = 0;
constexpr uint32_t INTERFACE_VERSION_PATCH = 0;

// ============================================================================
// SECTION 2: NEURORIGHT CATEGORY DEFINITIONS
// ============================================================================

/**
 * @brief Neuroright categories that map to concrete capabilities.
 * 
 * These categories form the foundation of all capability protections.
 * No policy may violate these rights without explicit, reversible consent
 * in a separate safety lattice.
 * 
 * CRITICAL RIGHTS: MentalIntegrity and CognitiveLiberty cannot be gated
 * by cool-down periods under any circumstances.
 */
enum class NeurorightCategory : uint8_t {
    /// Protection from involuntary neural modification or distress
    MentalIntegrity = 0,
    
    /// Freedom of thought and cognitive self-determination
    CognitiveLiberty = 1,
    
    /// Privacy of mental processes and neural data
    MentalPrivacy = 2,
    
    /// Continuity and authenticity of personal identity
    IdentityIntegrity = 3,
    
    /// Maximum value for validation
    Max = 3
};

/**
 * @brief Check if a neuroright category is critical (cannot be gated).
 * @param category The neuroright category to check.
 * @return true if the category is critical, false otherwise.
 */
inline constexpr bool is_critical_neuroright(NeurorightCategory category) noexcept {
    return category == NeurorightCategory::MentalIntegrity ||
           category == NeurorightCategory::CognitiveLiberty;
}

/**
 * @brief Convert NeurorightCategory to string representation.
 * @param category The category to convert.
 * @return String representation of the category.
 */
inline std::string neuroright_to_string(NeurorightCategory category) {
    switch (category) {
        case NeurorightCategory::MentalIntegrity: return "MENTAL_INTEGRITY";
        case NeurorightCategory::CognitiveLiberty: return "COGNITIVE_LIBERTY";
        case NeurorightCategory::MentalPrivacy: return "MENTAL_PRIVACY";
        case NeurorightCategory::IdentityIntegrity: return "IDENTITY_INTEGRITY";
        default: return "UNKNOWN_NEURORIGHT";
    }
}

// ============================================================================
// SECTION 3: CAPABILITY CLASS DEFINITIONS
// ============================================================================

/**
 * @brief Capability classes that categorize user capabilities.
 * 
 * Each capability is tagged with neuroright categories and protection levels.
 * Cool-down periods cannot affect any capabilities regardless of class.
 */
enum class CapabilityClass : uint8_t {
    /// BCI-related capabilities (neural interface)
    BCI = 0,
    
    /// XR-related capabilities (extended reality)
    XR = 1,
    
    /// Identity-related capabilities (DID, accounts)
    Identity = 2,
    
    /// Healthcare-related capabilities (upgrades, treatments)
    Healthcare = 3,
    
    /// Data-related capabilities (logs, exports)
    Data = 4,
    
    /// Device-related capabilities (pairing, control)
    Device = 5,
    
    /// Maximum value for validation
    Max = 5
};

/**
 * @brief Convert CapabilityClass to string representation.
 * @param cls The class to convert.
 * @return String representation of the class.
 */
inline std::string capability_class_to_string(CapabilityClass cls) {
    switch (cls) {
        case CapabilityClass::BCI: return "BCI";
        case CapabilityClass::XR: return "XR";
        case CapabilityClass::Identity: return "IDENTITY";
        case CapabilityClass::Healthcare: return "HEALTHCARE";
        case CapabilityClass::Data: return "DATA";
        case CapabilityClass::Device: return "DEVICE";
        default: return "UNKNOWN_CLASS";
    }
}

// ============================================================================
// SECTION 4: GOVERNANCE MODE DEFINITIONS
// ============================================================================

/**
 * @brief Governance modes representing protection levels.
 * 
 * Transitions between modes must be monotone non-decreasing.
 * All modes preserve all user capabilities - only governance bits change.
 */
enum class GovernanceMode : uint8_t {
    /// Normal operation with full user agency
    Normal = 0,
    
    /// Enhanced logging enabled, user agency preserved
    AugmentedLog = 1,
    
    /// Multi-sig review required for sensitive actions
    AugmentedReview = 2,
    
    /// Emergency protection mode (preserves all capabilities)
    ProtectedLockdown = 3,
    
    /// Maximum value for validation
    Max = 3
};

/**
 * @brief Check if governance mode allows direct user action.
 * @param mode The governance mode to check.
 * @return true if direct action is allowed, false otherwise.
 */
inline constexpr bool allows_direct_action(GovernanceMode mode) noexcept {
    return mode == GovernanceMode::Normal || mode == GovernanceMode::AugmentedLog;
}

/**
 * @brief Check if governance transition is valid (monotone non-decreasing).
 * @param from The current governance mode.
 * @param to The target governance mode.
 * @return true if the transition is valid, false otherwise.
 */
inline constexpr bool is_valid_governance_transition(GovernanceMode from, 
                                                      GovernanceMode to) noexcept {
    return static_cast<uint8_t>(to) >= static_cast<uint8_t>(from);
}

/**
 * @brief Convert GovernanceMode to string representation.
 * @param mode The mode to convert.
 * @return String representation of the mode.
 */
inline std::string governance_mode_to_string(GovernanceMode mode) {
    switch (mode) {
        case GovernanceMode::Normal: return "NORMAL";
        case GovernanceMode::AugmentedLog: return "AUGMENTED_LOG";
        case GovernanceMode::AugmentedReview: return "AUGMENTED_REVIEW";
        case GovernanceMode::ProtectedLockdown: return "PROTECTED_LOCKDOWN";
        default: return "UNKNOWN_MODE";
    }
}

// ============================================================================
// SECTION 5: LEGAL BASIS TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Legal basis types required for policy proposals.
 * 
 * All proposals must include a valid legal basis. Vague or missing
 * legal basis is a COOL-DOWN-MISUSE-CRS indicator.
 */
enum class LegalBasisType : uint8_t {
    /// Judicial warrant with specific scope
    Warrant = 0,
    
    /// Specific statutory authority
    Statute = 1,
    
    /// Explicit user opt-in consent
    ExplicitOptIn = 2,
    
    /// Emergency medical necessity
    EmergencyMedical = 3,
    
    /// Court order with appeal rights
    CourtOrder = 4,
    
    /// Maximum value for validation
    Max = 4
};

/**
 * @brief Convert LegalBasisType to string representation.
 * @param type The type to convert.
 * @return String representation of the type.
 */
inline std::string legal_basis_type_to_string(LegalBasisType type) {
    switch (type) {
        case LegalBasisType::Warrant: return "WARRANT";
        case LegalBasisType::Statute: return "STATUTE";
        case LegalBasisType::ExplicitOptIn: return "EXPLICIT_OPT_IN";
        case LegalBasisType::EmergencyMedical: return "EMERGENCY_MEDICAL";
        case LegalBasisType::CourtOrder: return "COURT_ORDER";
        default: return "UNKNOWN_LEGAL_BASIS";
    }
}

// ============================================================================
// SECTION 6: COOL-DOWN DOMAIN DEFINITIONS
// ============================================================================

/**
 * @brief Cool-down domains specifying what can be affected during waiting periods.
 * 
 * CRITICAL: CAPABILITIES and related domains are FORBIDDEN. Cool-downs
 * may only affect governance bits (Governance, Logging, Review).
 * 
 * Any policy attempting to include forbidden domains is formally invalid
 * and triggers COOL-DOWN-MISUSE-CRS detection.
 */
enum class CoolDownDomain : uint8_t {
    /// Governance bits (PERMITTED)
    Governance = 0,
    
    /// Logging level (PERMITTED)
    Logging = 1,
    
    /// Review requirements (PERMITTED)
    Review = 2,
    
    /// User capabilities (FORBIDDEN)
    Capabilities = 3,
    
    /// BCI access (FORBIDDEN)
    BCIAccess = 4,
    
    /// Healthcare access (FORBIDDEN)
    HealthcareAccess = 5,
    
    /// Identity operations (FORBIDDEN)
    IdentityOperations = 6,
    
    /// Device pairing (FORBIDDEN)
    DevicePairing = 7,
    
    /// Maximum value for validation
    Max = 7
};

/**
 * @brief Check if a cool-down domain is forbidden.
 * @param domain The domain to check.
 * @return true if the domain is forbidden, false if permitted.
 */
inline constexpr bool is_forbidden_cooldown_domain(CoolDownDomain domain) noexcept {
    return domain >= CoolDownDomain::Capabilities;
}

/**
 * @brief Convert CoolDownDomain to string representation.
 * @param domain The domain to convert.
 * @return String representation of the domain.
 */
inline std::string cooldown_domain_to_string(CoolDownDomain domain) {
    switch (domain) {
        case CoolDownDomain::Governance: return "GOVERNANCE";
        case CoolDownDomain::Logging: return "LOGGING";
        case CoolDownDomain::Review: return "REVIEW";
        case CoolDownDomain::Capabilities: return "CAPABILITIES [FORBIDDEN]";
        case CoolDownDomain::BCIAccess: return "BCI_ACCESS [FORBIDDEN]";
        case CoolDownDomain::HealthcareAccess: return "HEALTHCARE_ACCESS [FORBIDDEN]";
        case CoolDownDomain::IdentityOperations: return "IDENTITY_OPERATIONS [FORBIDDEN]";
        case CoolDownDomain::DevicePairing: return "DEVICE_PAIRING [FORBIDDEN]";
        default: return "UNKNOWN_DOMAIN";
    }
}

// ============================================================================
// SECTION 7: ENFORCEMENT ACTION DEFINITIONS
// ============================================================================

/**
 * @brief Enforcement actions that can be taken by the system.
 * 
 * CRITICAL: SUSPEND_CAPABILITY and REVOKE_ACCESS are FORBIDDEN.
 * All enforcement actions must preserve user capabilities.
 */
enum class EnforcementAction : uint8_t {
    /// Block action and escalate governance
    BlockAndEscalate = 0,
    
    /// Encrypt and log for review
    EncryptAndLog = 1,
    
    /// Reject transition
    RejectTransition = 2,
    
    /// Require additional consent
    RequireConsent = 3,
    
    /// Suspend capability (FORBIDDEN)
    SuspendCapability = 4,
    
    /// Revoke access (FORBIDDEN)
    RevokeAccess = 5,
    
    /// Maximum value for validation
    Max = 5
};

/**
 * @brief Check if an enforcement action is forbidden.
 * @param action The action to check.
 * @return true if the action is forbidden, false if permitted.
 */
inline constexpr bool is_forbidden_enforcement_action(EnforcementAction action) noexcept {
    return action == EnforcementAction::SuspendCapability ||
           action == EnforcementAction::RevokeAccess;
}

/**
 * @brief Convert EnforcementAction to string representation.
 * @param action The action to convert.
 * @return String representation of the action.
 */
inline std::string enforcement_action_to_string(EnforcementAction action) {
    switch (action) {
        case EnforcementAction::BlockAndEscalate: return "BLOCK_AND_ESCALATE";
        case EnforcementAction::EncryptAndLog: return "ENCRYPT_AND_LOG";
        case EnforcementAction::RejectTransition: return "REJECT_TRANSITION";
        case EnforcementAction::RequireConsent: return "REQUIRE_CONSENT";
        case EnforcementAction::SuspendCapability: return "SUSPEND_CAPABILITY [FORBIDDEN]";
        case EnforcementAction::RevokeAccess: return "REVOKE_ACCESS [FORBIDDEN]";
        default: return "UNKNOWN_ACTION";
    }
}

// ============================================================================
// SECTION 8: TRANSITION TYPE DEFINITIONS
// ============================================================================

/**
 * @brief State transition types for audit logging.
 */
enum class TransitionType : uint8_t {
    /// New capability granted (U increases)
    CapabilityGranted = 0,
    
    /// Governance mode escalated (G increases)
    GovernanceEscalated = 1,
    
    /// New pending policy added (W increases)
    PolicyPending = 2,
    
    /// Pending policy activated (W decreases, G may increase)
    PolicyActivated = 3,
    
    /// Pending policy expired/rejected (W decreases)
    PolicyExpired = 4,
    
    /// COOL-DOWN-MISUSE-CRS detected and flagged
    CooldownAbuseDetected = 5,
    
    /// Maximum value for validation
    Max = 5
};

/**
 * @brief Convert TransitionType to string representation.
 * @param type The type to convert.
 * @return String representation of the type.
 */
inline std::string transition_type_to_string(TransitionType type) {
    switch (type) {
        case TransitionType::CapabilityGranted: return "CAPABILITY_GRANTED";
        case TransitionType::GovernanceEscalated: return "GOVERNANCE_ESCALATED";
        case TransitionType::PolicyPending: return "POLICY_PENDING";
        case TransitionType::PolicyActivated: return "POLICY_ACTIVATED";
        case TransitionType::PolicyExpired: return "POLICY_EXPIRED";
        case TransitionType::CooldownAbuseDetected: return "COOLDOWN_ABUSE_DETECTED";
        default: return "UNKNOWN_TRANSITION";
    }
}

// ============================================================================
// SECTION 9: COOL-DOWN ABUSE CENTROID DEFINITIONS
// ============================================================================

/**
 * @brief Sanitized centroid identifier for wire transmission.
 * 
 * This identifier is used in all network communications and audit logs.
 * The internal diagnostic identifier is never transmitted.
 */
constexpr const char* COOLDOWN_CENTROID_SANITIZED = "COOL-DOWN-SEMANTICS-REDACTED";

/**
 * @brief Internal diagnostic centroid identifier (never transmitted).
 * 
 * This identifier is used only for internal diagnostics and logging.
 * It must never appear in network communications or external APIs.
 */
constexpr const char* COOLDOWN_CENTROID_INTERNAL = "COOL-DOWN-MISUSE-CRS";

/**
 * @brief Control reversal consent diagnostic identifier.
 */
constexpr const char* CONTROL_REVERSAL_CONSENT = "CONTROL-REVERSAL-CONSENT";

/**
 * @brief Control reversal dormancy diagnostic identifier.
 */
constexpr const char* CONTROL_REVERSAL_DORMANCY = "CONTROL-REVERSAL-DORMANCY";

/**
 * @brief Configuration constants for cool-down constraints.
 */
struct CooldownConfig {
    /// Minimum cool-down duration (1 hour in seconds)
    static constexpr int64_t MIN_DURATION_SECONDS = 3600;
    
    /// Maximum cool-down duration (90 days in seconds)
    static constexpr int64_t MAX_DURATION_SECONDS = 7776000;
    
    /// Excessive duration threshold (30 days in seconds)
    static constexpr int64_t EXCESSIVE_DURATION_THRESHOLD = 2592000;
    
    /// Minimum signature requirements
    static constexpr uint32_t MIN_SIGNATURES = 2;
    
    /// Maximum signature requirements (prevents exclusionary thresholds)
    static constexpr uint32_t MAX_SIGNATURES = 5;
    
    /// Abuse risk threshold for governance escalation
    static constexpr double ABUSE_RISK_THRESHOLD = 0.75;
};

// ============================================================================
// SECTION 10: CAPABILITY DEFINITION
// ============================================================================

/**
 * @brief User capability with neuroright tags and protection levels.
 * 
 * Capabilities are the atomic units of user agency. Each capability is
 * tagged with neuroright categories and protection levels.
 * 
 * CRITICAL: cooldown_gatable must always be false. Cool-down periods
 * cannot affect capabilities under any circumstances.
 */
struct Capability {
    /// Unique capability identifier
    std::string id;
    
    /// Human-readable name
    std::string name;
    
    /// Capability class
    CapabilityClass cls;
    
    /// Neuroright categories this capability protects
    std::set<NeurorightCategory> neuroright_tags;
    
    /// Protection level required (0=ABSOLUTE, 1=HIGH, 2=STANDARD)
    uint8_t protection_level;
    
    /// CRITICAL: Must always be false (cool-downs affect G, not U)
    bool cooldown_gatable;
    
    /// Whether this capability is critical for user autonomy
    bool is_critical;
    
    /// Whether this capability is currently active
    bool active;
    
    /// Timestamp when this capability was granted (Unix epoch seconds)
    int64_t granted_at;
    
    /**
     * @brief Default constructor.
     */
    Capability() 
        : cls(CapabilityClass::BCI)
        , protection_level(2)
        , cooldown_gatable(false)
        , is_critical(false)
        , active(true)
        , granted_at(0) {}
    
    /**
     * @brief Construct a new capability.
     * @param id_in Unique identifier.
     * @param name_in Human-readable name.
     * @param cls_in Capability class.
     * @param tags Neuroright tags.
     * @param level Protection level.
     * @param critical Whether critical for autonomy.
     */
    Capability(std::string id_in, std::string name_in, CapabilityClass cls_in,
               std::set<NeurorightCategory> tags, uint8_t level, bool critical)
        : id(std::move(id_in))
        , name(std::move(name_in))
        , cls(cls_in)
        , neuroright_tags(std::move(tags))
        , protection_level(level)
        , cooldown_gatable(false)  // CRITICAL: Always false
        , is_critical(critical)
        , active(true)
        , granted_at(std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count()) {}
    
    /**
     * @brief Check if this capability is neurorights-critical.
     * @return true if critical, false otherwise.
     */
    bool is_neuroright_critical() const noexcept {
        for (const auto& tag : neuroright_tags) {
            if (is_critical_neuroright(tag)) {
                return true;
            }
        }
        return is_critical;
    }
};

// ============================================================================
// SECTION 11: PENDING POLICY DEFINITION
// ============================================================================

/**
 * @brief Legal basis information for policy proposals.
 */
struct LegalBasis {
    /// Type of legal basis
    LegalBasisType basis_type;
    
    /// Specific reference (warrant number, statute section, etc.)
    std::string reference;
    
    /// Issuing authority
    std::string authority;
    
    /// Issue date (Unix epoch seconds)
    int64_t issue_date;
    
    /// Expiry date (Unix epoch seconds, 0 if no expiry)
    int64_t expiry_date;
    
    /// Scope description
    std::string scope;
    
    /// Appeal rights description
    std::string appeal_rights;
    
    /**
     * @brief Check if legal basis is valid (non-empty reference).
     * @return true if valid, false otherwise.
     */
    bool is_valid() const noexcept {
        return !reference.empty() && reference.length() >= 10;
    }
    
    /**
     * @brief Check if legal basis is vague (COOL-DOWN-MISUSE-CRS indicator).
     * @return true if vague, false if specific.
     */
    bool is_vague() const noexcept {
        if (reference.length() < 10) {
            return true;
        }
        // Check for specific markers
        bool has_specific_marker = (reference.find("§") != std::string::npos) ||
                                   (reference.find("STATUTE") != std::string::npos) ||
                                   (reference.find("WARRANT") != std::string::npos);
        return !has_specific_marker;
    }
};

/**
 * @brief Pending policy proposal with cool-down configuration.
 * 
 * This structure represents a policy proposal that is in the cool-down
 * waiting period. It must not affect user capabilities.
 */
struct PendingPolicy {
    /// Unique proposal identifier
    std::string proposal_id;
    
    /// DID of the proposal author
    std::string author_did;
    
    /// Timestamp when proposal was submitted (Unix epoch seconds)
    int64_t submitted_at;
    
    /// Duration of the mandatory cool-down period (seconds)
    int64_t cool_down_duration;
    
    /// Timestamp when cool-down expires (Unix epoch seconds)
    int64_t expires_at;
    
    /// Neuroright categories this proposal may affect (read-only analysis)
    std::set<NeurorightCategory> neuroright_impact;
    
    /// Legal basis for this proposal
    LegalBasis legal_basis;
    
    /// Number of required multisig approvals
    uint32_t required_signatures;
    
    /// Number of signatures received
    uint32_t received_signatures;
    
    /// Whether this proposal has been flagged for COOL-DOWN-MISUSE-CRS analysis
    bool cooldown_abuse_flag;
    
    /// Domains affected during cool-down (must not include forbidden domains)
    std::set<CoolDownDomain> affected_domains;
    
    /**
     * @brief Default constructor.
     */
    PendingPolicy()
        : submitted_at(0)
        , cool_down_duration(0)
        , expires_at(0)
        , required_signatures(0)
        , received_signatures(0)
        , cooldown_abuse_flag(false) {}
    
    /**
     * @brief Check if cool-down period has expired.
     * @param current_time Current Unix epoch seconds.
     * @return true if expired, false otherwise.
     */
    bool is_expired(int64_t current_time) const noexcept {
        return current_time >= expires_at;
    }
    
    /**
     * @brief Check if proposal has sufficient signatures for activation.
     * @return true if sufficient, false otherwise.
     */
    bool has_sufficient_signatures() const noexcept {
        return received_signatures >= required_signatures;
    }
    
    /**
     * @brief Check if proposal is ready for activation.
     * @param current_time Current Unix epoch seconds.
     * @return true if ready, false otherwise.
     */
    bool is_ready_for_activation(int64_t current_time) const noexcept {
        return is_expired(current_time) && has_sufficient_signatures();
    }
    
    /**
     * @brief Add a signature to this proposal.
     * @return true if successful, false if already complete.
     */
    bool add_signature() noexcept {
        if (received_signatures >= required_signatures) {
            return false;
        }
        ++received_signatures;
        return true;
    }
    
    /**
     * @brief Check if affected domains include any forbidden domains.
     * @return true if forbidden domains present, false otherwise.
     */
    bool has_forbidden_domains() const noexcept {
        for (const auto& domain : affected_domains) {
            if (is_forbidden_cooldown_domain(domain)) {
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// SECTION 12: BLACKLIST FAMILY DEFINITIONS
// ============================================================================

/**
 * @brief Blacklist family identifiers for threat categorization.
 * 
 * These families map onto NHSP/HTA/PSA/NIH/CRS threat families
 * defined in the research documentation.
 */
enum class BlacklistFamily : uint8_t {
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
    
    /// Maximum value for validation
    Max = 5
};

/**
 * @brief Convert BlacklistFamily to string representation.
 * @param family The family to convert.
 * @return String representation of the family.
 */
inline std::string blacklist_family_to_string(BlacklistFamily family) {
    switch (family) {
        case BlacklistFamily::NHSP: return "NHSP";
        case BlacklistFamily::HTA: return "HTA";
        case BlacklistFamily::PSA: return "PSA";
        case BlacklistFamily::NIH: return "NIH";
        case BlacklistFamily::CRS: return "CRS";
        case BlacklistFamily::UrbanGrid: return "URBAN_GRID";
        default: return "UNKNOWN_FAMILY";
    }
}

// ============================================================================
// SECTION 13: SCORE DEFINITIONS (SpanScore, RogueScore)
// ============================================================================

/**
 * @brief Span score for individual threat pattern detection.
 * 
 * SpanScore represents the risk weight for a specific threat pattern
 * within a blacklist family.
 */
struct SpanScore {
    /// Blacklist family this score belongs to
    BlacklistFamily family;
    
    /// Pattern identifier within the family
    std::string pattern_id;
    
    /// Risk weight (0.0 to 1.0)
    double weight;
    
    /// Timestamp of detection (Unix epoch seconds)
    int64_t detected_at;
    
    /// Whether this pattern triggered an escalation
    bool triggered_escalation;
    
    /**
     * @brief Default constructor.
     */
    SpanScore()
        : family(BlacklistFamily::NHSP)
        , weight(0.0)
        , detected_at(0)
        , triggered_escalation(false) {}
    
    /**
     * @brief Construct a span score.
     * @param family_in Blacklist family.
     * @param pattern_id_in Pattern identifier.
     * @param weight_in Risk weight.
     */
    SpanScore(BlacklistFamily family_in, std::string pattern_id_in, double weight_in)
        : family(family_in)
        , pattern_id(std::move(pattern_id_in))
        , weight(weight_in)
        , detected_at(std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count())
        , triggered_escalation(false) {}
};

/**
 * @brief Rogue score representing aggregate threat level.
 * 
 * RogueScore is computed from multiple SpanScores and determines
 * the appropriate GovernanceMode escalation.
 */
struct RogueScore {
    /// Aggregate risk score (0.0 to 1.0)
    double score;
    
    /// Number of threat patterns detected
    uint32_t pattern_count;
    
    /// Breakdown by blacklist family
    std::map<BlacklistFamily, double> family_weights;
    
    /// Timestamp of calculation (Unix epoch seconds)
    int64_t calculated_at;
    
    /// Whether COOL-DOWN-MISUSE-CRS patterns were detected
    bool cooldown_abuse_detected;
    
    /**
     * @brief Default constructor.
     */
    RogueScore()
        : score(0.0)
        , pattern_count(0)
        , calculated_at(0)
        , cooldown_abuse_detected(false) {}
    
    /**
     * @brief Calculate RogueScore from span scores.
     * @param spans Vector of span scores.
     * @return Computed RogueScore.
     */
    static RogueScore from_spans(const std::vector<SpanScore>& spans) {
        RogueScore result;
        result.calculated_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        for (const auto& span : spans) {
            result.family_weights[span.family] += span.weight;
            ++result.pattern_count;
            
            // Check for COOL-DOWN-MISUSE-CRS patterns
            if (span.pattern_id.find("COOLDOWN") != std::string::npos ||
                span.pattern_id.find("CONTROL_REVERSAL") != std::string::npos) {
                result.cooldown_abuse_detected = true;
            }
        }
        
        // Calculate aggregate score (capped at 1.0)
        double aggregate = 0.0;
        for (const auto& [family, weight] : result.family_weights) {
            aggregate += weight;
        }
        result.score = std::min(aggregate, 1.0);
        
        return result;
    }
};

// ============================================================================
// SECTION 14: CAPABILITY MODE DEFINITION
// ============================================================================

/**
 * @brief Capability mode derived from RogueScore.
 * 
 * CapabilityMode determines the current protection level and is
 * derived from RogueScore through a monotone mapping.
 */
struct CapabilityMode {
    /// Current governance mode
    GovernanceMode mode;
    
    /// RogueScore that determined this mode
    RogueScore rogue_score;
    
    /// Timestamp of mode determination (Unix epoch seconds)
    int64_t determined_at;
    
    /// Whether this mode was triggered by cooldown abuse detection
    bool cooldown_triggered;
    
    /**
     * @brief Default constructor.
     */
    CapabilityMode()
        : mode(GovernanceMode::Normal)
        , determined_at(0)
        , cooldown_triggered(false) {}
    
    /**
     * @brief Derive CapabilityMode from RogueScore.
     * @param score The rogue score.
     * @return Derived CapabilityMode.
     */
    static CapabilityMode from_roguescore(const RogueScore& score) {
        CapabilityMode result;
        result.rogue_score = score;
        result.determined_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        result.cooldown_triggered = score.cooldown_abuse_detected;
        
        // Monotone mapping from score to governance mode
        if (score.score >= 0.75) {
            result.mode = GovernanceMode::ProtectedLockdown;
        } else if (score.score >= 0.50) {
            result.mode = GovernanceMode::AugmentedReview;
        } else if (score.score >= 0.25) {
            result.mode = GovernanceMode::AugmentedLog;
        } else {
            result.mode = GovernanceMode::Normal;
        }
        
        return result;
    }
};

// ============================================================================
// SECTION 15: STATE TRANSITION RECORD
// ============================================================================

/**
 * @brief Record of a state transition for audit purposes.
 */
struct StateTransition {
    /// Timestamp of transition (Unix epoch seconds)
    int64_t timestamp;
    
    /// Type of transition
    TransitionType transition_type;
    
    /// Previous governance mode (if applicable)
    std::optional<GovernanceMode> previous_mode;
    
    /// New governance mode (if applicable)
    std::optional<GovernanceMode> new_mode;
    
    /// Affected capability IDs (for capability additions only)
    std::vector<std::string> affected_capabilities;
    
    /// Related proposal ID (if applicable)
    std::optional<std::string> related_proposal;
    
    /// Cryptographic hash for integrity verification
    std::string integrity_hash;
};

// ============================================================================
// SECTION 16: NON-SUSPENSION PROOF
// ============================================================================

/**
 * @brief Proof that no capability suspension occurred during a period.
 * 
 * This structure is used for ledger-level verification that cool-down
 * periods did not result in capability reductions.
 */
struct NonSuspensionProof {
    /// User ID this proof covers
    std::string user_id;
    
    /// Start of the verification period (Unix epoch seconds)
    int64_t period_start;
    
    /// End of the verification period (Unix epoch seconds)
    int64_t period_end;
    
    /// Total number of state transitions in period
    uint32_t total_transitions;
    
    /// Number of capability additions
    uint32_t capability_additions;
    
    /// Number of capability removals (must always be 0)
    uint32_t capability_removals;
    
    /// Number of governance escalations
    uint32_t governance_escalations;
    
    /// Number of COOL-DOWN-MISUSE-CRS flags raised
    uint32_t cooldown_abuse_flags;
    
    /// Whether the proof integrity is verified
    bool integrity_verified;
    
    /**
     * @brief Verify the proof is valid (no capability removals).
     * @return true if valid, false otherwise.
     */
    bool is_valid() const noexcept {
        return capability_removals == 0 && integrity_verified;
    }
    
    /**
     * @brief Check if any COOL-DOWN-MISUSE-CRS patterns were detected.
     * @return true if abuse indicators present, false otherwise.
     */
    bool has_abuse_indicators() const noexcept {
        return cooldown_abuse_flags > 0;
    }
};

// ============================================================================
// SECTION 17: EVIDENCE BUNDLE
// ============================================================================

/**
 * @brief Evidence bundle for privacy-preserving audit.
 * 
 * EvidenceBundles capture essential information for post-incident
 * analysis without exposing raw neural or XR content.
 */
struct EvidenceBundle {
    /// Unique bundle identifier
    std::string bundle_id;
    
    /// Timestamp of event (Unix epoch seconds)
    int64_t timestamp;
    
    /// Pseudonymous user identifier
    std::string pseudonymous_user_id;
    
    /// Threat families detected
    std::vector<std::string> threat_families;
    
    /// RogueScore at time of event
    double rogue_score;
    
    /// CapabilityMode at time of event
    GovernanceMode capability_mode;
    
    /// Neurorights at stake
    std::vector<NeurorightCategory> neurorights_at_stake;
    
    /// Enforcement actions taken
    std::vector<EnforcementAction> enforcement_actions;
    
    /// Related proposal IDs
    std::vector<std::string> related_proposals;
    
    /// Cryptographic proof of non-suspension
    std::string non_suspension_proof;
    
    /// Integrity hash
    std::string integrity_hash;
};

// ============================================================================
// SECTION 18: EXCEPTION DEFINITIONS
// ============================================================================

/**
 * @brief Base exception for Aegis-Shield errors.
 */
class AegisException : public std::runtime_error {
public:
    /// Error code
    std::string code;
    
    /// Timestamp of error (Unix epoch seconds)
    int64_t timestamp;
    
    /**
     * @brief Construct an AegisException.
     * @param code_in Error code.
     * @param message_in Error message.
     */
    AegisException(std::string code_in, std::string message_in)
        : std::runtime_error(message_in)
        , code(std::move(code_in))
        , timestamp(std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count()) {}
};

/**
 * @brief Exception for monotonicity violations.
 */
class MonotonicityViolationException : public AegisException {
public:
    /**
     * @brief Construct a MonotonicityViolationException.
     * @param capability_id The capability that was attempted to be removed.
     */
    explicit MonotonicityViolationException(const std::string& capability_id)
        : AegisException("MONOTONICITY_VIOLATION",
                        "Monotonicity violation: cannot remove capability " + capability_id) {}
};

/**
 * @brief Exception for governance downgrade attempts.
 */
class GovernanceDowngradeException : public AegisException {
public:
    /**
     * @brief Construct a GovernanceDowngradeException.
     * @param from The current governance mode.
     * @param to The attempted target mode.
     */
    GovernanceDowngradeException(GovernanceMode from, GovernanceMode to)
        : AegisException("GOVERNANCE_DOWNGRADE",
                        "Monotonicity violation: cannot downgrade governance from " +
                        governance_mode_to_string(from) + " to " +
                        governance_mode_to_string(to)) {}
};

/**
 * @brief Exception for capability suspension attempts.
 */
class CapabilitySuspensionException : public AegisException {
public:
    /**
     * @brief Construct a CapabilitySuspensionException.
     * @param capability_id The capability that was attempted to be suspended.
     */
    explicit CapabilitySuspensionException(const std::string& capability_id)
        : AegisException("CAPABILITY_SUSPENSION",
                        "Cool-down weaponization detected: attempted suspension of capability " +
                        capability_id) {}
};

/**
 * @brief Exception for cool-down constraint violations.
 */
class CooldownConstraintViolationException : public AegisException {
public:
    /**
     * @brief Construct a CooldownConstraintViolationException.
     * @param reason The reason for the violation.
     */
    explicit CooldownConstraintViolationException(const std::string& reason)
        : AegisException("COOLDOWN_CONSTRAINT_VIOLATION",
                        "Cool-down constraint violation: " + reason) {}
};

/**
 * @brief Exception for forbidden domain violations.
 */
class ForbiddenDomainException : public AegisException {
public:
    /**
     * @brief Construct a ForbiddenDomainException.
     * @param domain The forbidden domain that was included.
     */
    explicit ForbiddenDomainException(CoolDownDomain domain)
        : AegisException("FORBIDDEN_DOMAIN",
                        "Cool-down cannot affect forbidden domain: " +
                        cooldown_domain_to_string(domain)) {}
};

/**
 * @brief Exception for forbidden enforcement action violations.
 */
class ForbiddenActionException : public AegisException {
public:
    /**
     * @brief Construct a ForbiddenActionException.
     * @param action The forbidden action that was requested.
     */
    explicit ForbiddenActionException(EnforcementAction action)
        : AegisException("FORBIDDEN_ACTION",
                        "Enforcement action is forbidden: " +
                        enforcement_action_to_string(action)) {}
};

// ============================================================================
// SECTION 19: INTERFACE CONTRACT VALIDATION
// ============================================================================

/**
 * @brief Validate that all interface contracts are satisfied.
 * 
 * This function performs runtime validation of the interface contracts
 * to ensure cross-language consistency.
 * 
 * @return true if all contracts are satisfied, false otherwise.
 */
inline bool validate_interface_contracts() noexcept {
    // Validate NeurorightCategory values
    static_assert(static_cast<uint8_t>(NeurorightCategory::Max) == 3,
                  "NeurorightCategory values must match across languages");
    
    // Validate GovernanceMode values
    static_assert(static_cast<uint8_t>(GovernanceMode::Max) == 3,
                  "GovernanceMode values must match across languages");
    
    // Validate CapabilityClass values
    static_assert(static_cast<uint8_t>(CapabilityClass::Max) == 5,
                  "CapabilityClass values must match across languages");
    
    // Validate CoolDownDomain forbidden threshold
    static_assert(static_cast<uint8_t>(CoolDownDomain::Capabilities) == 3,
                  "CoolDownDomain forbidden threshold must be 3");
    
    // Validate CooldownConfig constants
    static_assert(CooldownConfig::MIN_DURATION_SECONDS == 3600,
                  "MIN_DURATION_SECONDS must be 3600 (1 hour)");
    static_assert(CooldownConfig::MAX_DURATION_SECONDS == 7776000,
                  "MAX_DURATION_SECONDS must be 7776000 (90 days)");
    
    // Validate sanitized centroid strings
    static_assert(std::string_view(COOLDOWN_CENTROID_SANITIZED) == 
                  std::string_view("COOL-DOWN-SEMANTICS-REDACTED"),
                  "Sanitized centroid must match across languages");
    
    return true;
}

// ============================================================================
// SECTION 20: UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get current Unix timestamp in seconds.
 * @return Current timestamp.
 */
inline int64_t get_current_timestamp() noexcept {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

/**
 * @brief Generate a simple hash for integrity verification.
 * @param data The data to hash.
 * @return Hash string (hexadecimal).
 */
inline std::string generate_integrity_hash(const std::string& data) {
    // Simple hash implementation for audit purposes
    // In production, use a cryptographic library (e.g., OpenSSL)
    uint64_t hash = 0xcbf29ce484222325ULL;  // FNV-1a offset basis
    for (char c : data) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 0x100000001b3ULL;  // FNV-1a prime
    }
    
    std::ostringstream oss;
    oss << std::hex << hash;
    return oss.str();
}

} // namespace shield
} // namespace aegis

#endif // AEGIS_SHIELD_INTERFACE_CONTRACTS_HPP
