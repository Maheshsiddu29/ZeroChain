//! Command handlers

pub mod keypair;
pub mod shield;
pub mod scan;
pub mod transfer;
pub mod update_root;
pub mod set_vk;
pub mod import_note;
pub mod validator;
pub mod nullifier;
pub mod prover;
pub mod monitor;

pub use keypair::handle_keypair;
pub use shield::handle_shield;
pub use scan::handle_scan;
pub use transfer::{handle_submit_shielded_transfer, handle_transfer};
pub use update_root::handle_update_root;
pub use set_vk::handle_set_vk;
pub use import_note::handle_import_note;
pub use validator::{handle_register_validator, handle_query_validator_set, handle_query_validator};
pub use nullifier::handle_check_nullifier;
pub use prover::handle_generate_lineage_proof;
pub use monitor::handle_monitor;