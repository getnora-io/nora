#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::validation::{
    namespace_match, validate_digest, validate_docker_name, validate_docker_reference,
    validate_storage_key,
};

fuzz_target!(|data: &str| {
    // Fuzz all validators — they must never panic on any input
    let _ = validate_storage_key(data);
    let _ = validate_docker_name(data);
    let _ = validate_digest(data);
    let _ = validate_docker_reference(data);

    // #861: intra-segment `*` wildcards in namespace_scope patterns. The glob
    // matcher must never panic, recurse to stack overflow, or blow up
    // super-linearly on adversarial pattern×value pairs. Split on the first
    // space to feed an independent pattern and value; otherwise exercise the
    // whole input as both.
    let (pattern, value) = data.split_once(' ').unwrap_or((data, data));
    let _ = namespace_match(pattern, value);
});
