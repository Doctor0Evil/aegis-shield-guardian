// src/identities.rs
#[derive(Debug, Clone)]
pub struct StakeholderIdentity {
    pub bostrom_primary:   String,
    pub bostrom_alt:       String,
    pub safe_alt_1:        String,
    pub safe_alt_2_evm:    String,
}

impl Default for StakeholderIdentity {
    fn default() -> Self {
        Self {
            bostrom_primary: "bostrom18sd2ujv24ual9c9pshtxys6j8knh6xaead9ye7".into(),
            bostrom_alt:     "bostrom1ldgmtf20d6604a24ztr0jxht7xt7az4jhkmsrc".into(),
            safe_alt_1:      "zeta12x0up66pzyeretzyku8p4ccuxrjqtqpdc4y4x8".into(),
            safe_alt_2_evm:  "0x519fC0eB4111323Cac44b70e1aE31c30e405802D".into(),
        }
    }
}
