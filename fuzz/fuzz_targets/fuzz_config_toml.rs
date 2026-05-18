#![no_main]
use libfuzzer_sys::fuzz_target;
use nora_registry::validation::{
    ends_with_ci, validate_digest, validate_docker_name, validate_docker_reference,
    validate_storage_key,
};

fuzz_target!(|data: &str| {
    // Extended validation fuzzing: covers edge cases not in fuzz_validation
    // Focus on interaction between validators and helpers

    // ends_with_ci with arbitrary suffix — must never panic
    let _ = ends_with_ci(data, ".tar.gz");
    let _ = ends_with_ci(data, ".whl");
    let _ = ends_with_ci(data, ".nupkg");
    let _ = ends_with_ci(data, "");
    let _ = ends_with_ci("", data);

    // Validators with pathological inputs
    // Long strings, unicode, null bytes, control chars
    let _ = validate_storage_key(data);
    let _ = validate_docker_name(data);
    let _ = validate_digest(data);
    let _ = validate_docker_reference(data);

    // Compound: path-like strings through storage key
    if data.len() < 512 {
        let compound = format!("docker/{}/manifests/latest", data);
        let _ = validate_storage_key(&compound);
        let maven_path = format!("com/example/{}/1.0/file.jar", data);
        let _ = validate_storage_key(&maven_path);
    }
});
