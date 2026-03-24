use serde::Deserialize;

#[derive(Deserialize)]
pub struct PolicyRule {

    pub id: String,

    pub family: String,

    pub neurorights: Vec<String>,

    pub enforcementhint: String,
}

pub fn load_policies(path: &str) -> Vec<PolicyRule> {

    let data = std::fs::read_to_string(path).unwrap();

    serde_yaml::from_str(&data).unwrap()
}
