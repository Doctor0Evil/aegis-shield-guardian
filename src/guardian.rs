// src/guardian.rs
use doctorlabssuperfilter::{SpanScore, RogueScore, RogueConfig, CapabilityMode};
use crate::capability_lattice::{CapabilityState, CapabilityTransition};

#[derive(Debug, Clone)]
pub struct AegisDecision {
    pub roguescore: RogueScore,
    pub mode:       CapabilityMode,
    pub next_state: CapabilityState,
}

#[derive(Debug, Clone)]
pub struct AegisGuardian {
    pub cfg:        RogueConfig,
    pub base_state: CapabilityState,
}

impl AegisGuardian {
    pub fn new(cfg: RogueConfig, base_state: CapabilityState) -> Self {
        Self { cfg, base_state }
    }

    pub fn decide(&self, spans: &[SpanScore]) -> AegisDecision {
        let r = RogueScore::from_spans(spans.to_vec(), self.cfg.clone());
        let mode = CapabilityMode::from_rogue_score(r, self.cfg.clone());

        let mut next = self.base_state.clone();
        match mode {
            CapabilityMode::Normal => { /* no change */ }
            CapabilityMode::AugmentedLog => {
                next.gov_caps.insert(crate::capability_lattice::CapabilityBit::LogAccess);
            }
            CapabilityMode::AugmentedReview => {
                next.gov_caps.insert(crate::capability_lattice::CapabilityBit::LogAccess);
                next.gov_caps.insert(crate::capability_lattice::CapabilityBit::EvidenceExport);
            }
        }

        let tr = CapabilityTransition { from: self.base_state.clone(), to: next.clone() };
        assert!(tr.is_monotone(), "non‑monotone transition forbidden by Aegis‑Shield");

        AegisDecision { roguescore: r, mode, next_state: next }
    }
}
