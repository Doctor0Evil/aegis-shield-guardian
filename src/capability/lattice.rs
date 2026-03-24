use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityBit {

    ChatUse,
    DeviceAccess,
    BciIo,
    XRInterface,
    KeyManagement,

    LogAccess,
    EvidenceExport,
    PolicyInspection,
}

#[derive(Debug, Clone)]
pub struct CapabilityState {

    pub user_caps: BTreeSet<CapabilityBit>,
    pub gov_caps: BTreeSet<CapabilityBit>,
}

impl CapabilityState {

    pub fn is_subset_of(&self, other: &Self) -> bool {

        self.user_caps.is_subset(&other.user_caps)
        && self.gov_caps.is_subset(&other.gov_caps)
    }
}
