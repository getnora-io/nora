use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nora_registry::validation::{
    validate_digest, validate_docker_name, validate_docker_reference, validate_storage_key,
};

fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");

    group.bench_function("storage_key_short", |b| {
        b.iter(|| validate_storage_key(black_box("docker/alpine/blobs/sha256:abc123")))
    });

    group.bench_function("storage_key_long", |b| {
        let key = "maven/com/example/deep/nested/path/artifact-1.0.0-SNAPSHOT.jar";
        b.iter(|| validate_storage_key(black_box(key)))
    });

    group.bench_function("storage_key_reject", |b| {
        b.iter(|| validate_storage_key(black_box("../etc/passwd")))
    });

    group.bench_function("docker_name_simple", |b| {
        b.iter(|| validate_docker_name(black_box("library/alpine")))
    });

    group.bench_function("docker_name_nested", |b| {
        b.iter(|| validate_docker_name(black_box("my-org/sub/repo-name")))
    });

    group.bench_function("docker_name_reject", |b| {
        b.iter(|| validate_docker_name(black_box("INVALID/NAME")))
    });

    group.bench_function("digest_sha256", |b| {
        b.iter(|| {
            validate_digest(black_box(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ))
        })
    });

    group.bench_function("digest_reject", |b| {
        b.iter(|| validate_digest(black_box("md5:abc")))
    });

    group.bench_function("reference_tag", |b| {
        b.iter(|| validate_docker_reference(black_box("v1.2.3-alpine")))
    });

    group.bench_function("reference_digest", |b| {
        b.iter(|| {
            validate_docker_reference(black_box(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ))
        })
    });

    group.finish();
}

fn bench_manifest_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("manifest_detection");

    let docker_v2 = serde_json::json!({
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "schemaVersion": 2,
        "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": "sha256:abc"},
        "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "digest": "sha256:def", "size": 1000}]
    })
    .to_string();

    let oci_index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [
            {"digest": "sha256:aaa", "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:bbb", "platform": {"os": "linux", "architecture": "arm64"}}
        ]
    })
    .to_string();

    let minimal = serde_json::json!({"schemaVersion": 2}).to_string();

    group.bench_function("docker_v2_explicit", |b| {
        b.iter(|| {
            nora_registry::docker_fuzz::detect_manifest_media_type(black_box(docker_v2.as_bytes()))
        })
    });

    group.bench_function("oci_index", |b| {
        b.iter(|| {
            nora_registry::docker_fuzz::detect_manifest_media_type(black_box(oci_index.as_bytes()))
        })
    });

    group.bench_function("minimal_json", |b| {
        b.iter(|| {
            nora_registry::docker_fuzz::detect_manifest_media_type(black_box(minimal.as_bytes()))
        })
    });

    group.bench_function("invalid_json", |b| {
        b.iter(|| nora_registry::docker_fuzz::detect_manifest_media_type(black_box(b"not json")))
    });

    group.finish();
}

criterion_group!(benches, bench_validation, bench_manifest_detection);
criterion_main!(benches);
