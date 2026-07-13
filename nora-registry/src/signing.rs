// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Repository index signing (#128).
//!
//! Holds one OpenPGP signing key per NORA instance and produces the three
//! signature shapes package managers verify: a clearsigned document (APT
//! `InRelease`), a detached armored signature (APT `Release.gpg`, yum
//! `repomd.xml.asc`), and the armored public key clients import.
//!
//! The key is a v4 Ed25519 ("Ed25519Legacy") primary with no passphrase —
//! the variant every deployed verifier understands (gpgv on apt's side,
//! gnupg via librepo on dnf's side); the RFC 9580 v6 algorithms are not yet
//! recognized by either. Generated on first boot and persisted armored at
//! the configured path, so a restart keeps the same identity. Key material
//! never passes through config or env; only a filesystem path does.
//!
//! The key is SINGLE-WRITER: it lives on the local filesystem even when
//! artifacts live in an object store. Running multiple replicas requires
//! the same key bytes at `signing.key_path` on every replica — provision
//! the key once and mount it read-only everywhere (e.g. a Kubernetes
//! Secret), or share a ReadWriteMany volume. Replicas that each generate
//! their own key serve clients a public key that fails to verify indexes
//! signed by their siblings.

use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, KeyType,
    SecretKeyParamsBuilder, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails, Password};
use std::io::Cursor;
use std::path::Path;
use zeroize::Zeroizing;

/// Signing identity attached to the generated key.
const USER_ID: &str = "NORA repository signing";

pub struct RepoSigner {
    key: SignedSecretKey,
    public_armored: String,
    fingerprint: String,
    /// True when this process generated the key on this boot (first boot or
    /// race winner) — lets startup warn about generation on ephemeral paths.
    generated: bool,
}

impl RepoSigner {
    /// Load the signing key from `path`, or generate and persist one on
    /// first boot. Fail-closed: any error other than "file absent" is
    /// returned, never papered over with a fresh key — silently rotating
    /// the key would invalidate every client's pinned public key.
    pub fn load_or_generate(path: &Path) -> Result<Self, String> {
        let mut generated = false;
        let key = match std::fs::read_to_string(path).map(Zeroizing::new) {
            Ok(armored) => {
                let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored.as_str()))
                    .map_err(|e| format!("parse signing key {}: {e}", path.display()))?;
                key
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = generate_key()?;
                match persist_key(&key, path)? {
                    Persisted::Written => {
                        tracing::info!(path = %path.display(), "generated new repository signing key");
                        generated = true;
                        key
                    }
                    // A concurrent first boot won the create — discard the
                    // fresh key and adopt the winner's, or every replica
                    // would sign with a different identity for its lifetime.
                    Persisted::LostRace => {
                        let armored =
                            Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
                                format!("re-read signing key {}: {e}", path.display())
                            })?);
                        let (key, _) =
                            SignedSecretKey::from_armor_single(Cursor::new(armored.as_str()))
                                .map_err(|e| {
                                    format!("parse signing key {}: {e}", path.display())
                                })?;
                        key
                    }
                }
            }
            Err(e) => return Err(format!("read signing key {}: {e}", path.display())),
        };

        let public = key
            .to_public_key()
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("armor public key: {e}"))?;
        let fingerprint = key.fingerprint().to_string();
        Ok(Self {
            key,
            public_armored: public,
            fingerprint,
            generated,
        })
    }

    /// True when the key was generated (not loaded) on this boot.
    pub fn was_generated(&self) -> bool {
        self.generated
    }

    /// Clearsign `text` (APT `InRelease`).
    pub fn clearsign(&self, text: &str) -> Result<String, String> {
        CleartextSignedMessage::sign(rand::thread_rng(), text, &*self.key, &Password::empty())
            .and_then(|m| m.to_armored_string(ArmorOptions::default()))
            .map_err(|e| format!("clearsign: {e}"))
    }

    /// Detached armored signature over `data` (APT `Release.gpg`, yum
    /// `repomd.xml.asc`).
    pub fn sign_detached(&self, data: &[u8]) -> Result<String, String> {
        DetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &*self.key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        )
        .and_then(|s| s.to_armored_string(ArmorOptions::default()))
        .map_err(|e| format!("detached sign: {e}"))
    }

    /// Armored public key for client import (`repomd.xml.key`, `pubkey.gpg`).
    pub fn public_key_armored(&self) -> &str {
        &self.public_armored
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

fn generate_key() -> Result<SignedSecretKey, String> {
    SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_sign(true)
        .primary_user_id(USER_ID.into())
        .build()
        .map_err(|e| format!("signing key params: {e}"))?
        .generate(rand::thread_rng())
        .map_err(|e| format!("generate signing key: {e}"))
}

/// Write the armored secret key with owner-only permissions, creating the
/// parent directory. Staged to a per-process temp file, then claimed with a
/// create-exclusive link: exactly one of N concurrent first boots wins;
/// losers get [`Persisted::LostRace`] and must adopt the winner's key. A
/// crash never leaves a half-written key at the final path.
enum Persisted {
    Written,
    /// Another process created the key between our read and our write.
    LostRace,
}

fn persist_key(key: &SignedSecretKey, path: &Path) -> Result<Persisted, String> {
    let armored = Zeroizing::new(
        key.to_armored_string(ArmorOptions::default())
            .map_err(|e| format!("armor signing key: {e}"))?,
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    // Unique per CALL, not per process — concurrent threads in one process
    // (or pid reuse across containers) must never share a staging file, or
    // the link winner can publish bytes some other caller staged.
    static STAGE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "key.tmp.{}.{}",
        std::process::id(),
        STAGE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&tmp, armored.as_bytes())
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    }
    // hard_link is create-exclusive (EEXIST if a concurrent boot already won),
    // unlike rename which silently replaces.
    let outcome = match std::fs::hard_link(&tmp, path) {
        Ok(()) => Persisted::Written,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Persisted::LostRace,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("link to {}: {e}", path.display()));
        }
    };
    let _ = std::fs::remove_file(&tmp);
    Ok(outcome)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_persist_reload_same_identity() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("signing").join("nora.key");

        let first = RepoSigner::load_or_generate(&path).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key must be owner-only");
        }

        let second = RepoSigner::load_or_generate(&path).unwrap();
        assert_eq!(
            first.fingerprint(),
            second.fingerprint(),
            "reload must keep the same key, not rotate"
        );
        assert_eq!(first.public_key_armored(), second.public_key_armored());
    }

    /// N concurrent first boots must all end up with the SAME identity —
    /// the create-exclusive claim means one generator wins and every loser
    /// adopts the winner's key instead of serving its own for its lifetime.
    #[test]
    fn concurrent_first_boot_converges_on_one_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nora.key");
        let fingerprints: Vec<String> = std::thread::scope(|s| {
            (0..8)
                .map(|_| {
                    s.spawn(|| {
                        RepoSigner::load_or_generate(&path)
                            .unwrap()
                            .fingerprint()
                            .to_string()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect()
        });
        assert!(
            fingerprints.windows(2).all(|w| w[0] == w[1]),
            "replicas diverged: {fingerprints:?}"
        );
        // No stray temp files left behind by the losers.
        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().into_string().unwrap())
            .filter(|n| n.contains("tmp"))
            .collect();
        assert!(strays.is_empty(), "stray temp files: {strays:?}");
    }

    #[test]
    fn corrupt_key_fails_closed() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nora.key");
        std::fs::write(&path, "not a pgp key").unwrap();
        let err = RepoSigner::load_or_generate(&path).err().unwrap();
        assert!(err.contains("parse signing key"), "{err}");
        // The corrupt file must not be overwritten with a fresh key.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not a pgp key");
    }

    #[test]
    fn detached_signature_verifies_and_clearsign_roundtrips() {
        let dir = tempfile::TempDir::new().unwrap();
        let signer = RepoSigner::load_or_generate(&dir.path().join("k.key")).unwrap();

        let data = b"repomd contents";
        let armored = signer.sign_detached(data).unwrap();
        assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----"));
        let (sig, _) =
            DetachedSignature::from_armor_single(std::io::Cursor::new(armored.as_bytes())).unwrap();
        sig.verify(&signer.key.to_public_key(), data).unwrap();

        let clear = signer.clearsign("Origin: NORA\nLabel: test\n").unwrap();
        assert!(clear.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
        let (msg, _) =
            CleartextSignedMessage::from_armor(std::io::Cursor::new(clear.as_bytes())).unwrap();
        msg.verify(&signer.key.to_public_key()).unwrap();
        assert!(msg.signed_text().contains("Origin: NORA"));

        let public = signer.public_key_armored();
        assert!(public.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod real_verifier_tests {
    //! Closes the round-trip-vs-acceptance gap: rPGP verifying its own output
    //! proves consistency, not that gpgv/gnupg (what apt and librepo actually
    //! run) accept it. Ignored by default — requires `gpg` and `gpgv` on PATH;
    //! run with `cargo test -- --ignored real_verifier`.
    use super::*;
    use std::process::Command;

    fn run(cmd: &mut Command) -> (bool, String) {
        match cmd.output() {
            Ok(o) => (
                o.status.success(),
                format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            ),
            Err(e) => (false, e.to_string()),
        }
    }

    #[test]
    #[ignore = "requires gpg + gpgv on PATH"]
    fn real_verifier_accepts_all_signature_shapes() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("gnupghome");
        std::fs::create_dir(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let signer = RepoSigner::load_or_generate(&dir.path().join("nora.key")).unwrap();

        // The exact bytes NORA serves: pubkey, detached sigs, clearsigned doc.
        let release = "Origin: NORA\nLabel: test\nDate: Sat, 12 Jul 2026 12:00:00 UTC\nSHA256:\n abc123 1 Packages\n";
        let repomd = b"<?xml version=\"1.0\"?><repomd></repomd>";
        let w = |name: &str, data: &[u8]| {
            let p = dir.path().join(name);
            std::fs::write(&p, data).unwrap();
            p
        };
        let pubkey = w("pubkey.gpg", signer.public_key_armored().as_bytes());
        let release_f = w("Release", release.as_bytes());
        let release_gpg = w(
            "Release.gpg",
            signer.sign_detached(release.as_bytes()).unwrap().as_bytes(),
        );
        let inrelease = w("InRelease", signer.clearsign(release).unwrap().as_bytes());
        let repomd_f = w("repomd.xml", repomd);
        let repomd_asc = w(
            "repomd.xml.asc",
            signer.sign_detached(repomd).unwrap().as_bytes(),
        );

        // gpg --import the served public key (librepo's flow for repo_gpgcheck).
        let (ok, out) = run(Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--batch", "--import"])
            .arg(&pubkey));
        assert!(ok, "gpg --import rejected the served public key:\n{out}");

        // Dearmored keyring for gpgv (it reads keyring files, not armored keys).
        let keyring = dir.path().join("keyring.gpg");
        let (ok, out) = run(Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--batch", "--yes", "-o"])
            .arg(&keyring)
            .args(["--dearmor"])
            .arg(&pubkey));
        assert!(ok, "gpg --dearmor failed:\n{out}");

        // apt flow 1: detached Release.gpg over Release.
        let (ok, out) = run(Command::new("gpgv")
            .arg("--keyring")
            .arg(&keyring)
            .arg(&release_gpg)
            .arg(&release_f));
        assert!(ok, "gpgv rejected Release.gpg/Release:\n{out}");

        // apt flow 2: clearsigned InRelease.
        let (ok, out) = run(Command::new("gpgv")
            .arg("--keyring")
            .arg(&keyring)
            .arg(&inrelease));
        assert!(ok, "gpgv rejected InRelease:\n{out}");

        // dnf/librepo flow: detached armored sig over repomd.xml.
        let (ok, out) = run(Command::new("gpg")
            .env("GNUPGHOME", &home)
            .args(["--batch", "--verify"])
            .arg(&repomd_asc)
            .arg(&repomd_f));
        assert!(ok, "gpg --verify rejected repomd.xml.asc:\n{out}");
    }
}
