pub struct StakeholderIdentity {

    pub bostrom_primary: String,

    pub bostrom_secondary: String,

    pub evm_wallet: String,
}

impl StakeholderIdentity {

    pub fn load_default() -> Self {

        Self {

            bostrom_primary:
                "bostrom18sd2ujv24ual9c9pshtxys6j8knh6xaead9ye7".into(),

            bostrom_secondary:
                "bostrom1ldgmtf20d6604a24ztr0jxht7xt7az4jhkmsrc".into(),

            evm_wallet:
                "0x519fC0eB4111323Cac44b70e1aE31c30e405802D".into(),
        }
    }
}
