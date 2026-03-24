use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityBit {
    ChatUse,
    BciIo,
    XrOverlay,
    KeyManagement,
    LogAccess,
    EvidenceExport,
}

#[derive(Debug, Clone)]
pub struct CapabilityState {
    pub user_caps: BTreeSet<CapabilityBit>,
    pub gov_caps:  BTreeSet<CapabilityBit>,
}

impl CapabilityState {
    pub fn leq(&self, other: &Self) -> bool {
        self.user_caps.is_subset(&other.user_caps)
            && self.gov_caps.is_subset(&other.gov_caps)
    }

    pub fn join(&self, other: &Self) -> Self {
        let mut u = self.user_caps.clone();
        u.extend(other.user_caps.iter().copied());
        let mut g = self.gov_caps.clone();
        g.extend(other.gov_caps.iter().copied());
        Self { user_caps: u, gov_caps: g }
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityTransition {
    pub from: CapabilityState,
    pub to:   CapabilityState,
}

impl CapabilityTransition {
    pub fn is_monotone(&self) -> bool {
        self.from.leq(&self.to)
    }
}
