// src/lib.rs
pub mod capability_lattice;
pub mod guardian;
pub mod policy_loader;
pub mod identities;
pub mod http_gateway;

pub use capability_lattice::{CapabilityBit, CapabilityState, CapabilityTransition};
pub use guardian::{AegisGuardian, AegisDecision};
