#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::validation::{
    validate_digest, validate_docker_name, validate_docker_reference, validate_storage_key,
};

fuzz_target!(|data: &str| {
    // Fuzz all validators — they must never panic on any input
    let _ = validate_storage_key(data);
    let _ = validate_docker_name(data);
    let _ = validate_digest(data);
    let _ = validate_docker_reference(data);
});
