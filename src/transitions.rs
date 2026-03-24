use super::lattice::CapabilityState;

pub struct Transition {

    pub from: CapabilityState,
    pub to: CapabilityState,
}

impl Transition {

    pub fn verify_monotone(&self) -> bool {

        self.from.is_subset_of(&self.to)
    }
}
