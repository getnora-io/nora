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
//! the configured path, so a restart — or a replica sharing the path —
//! keeps the same identity. Key material never passes through config or
//! env; only a filesystem path does.

use pgp::composed::{
    ArmorOptions, CleartextSignedMessage, Deserializable, DetachedSignature, KeyType,
    SecretKeyParamsBuilder, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails, Password};
use std::io::Cursor;
use std::path::Path;

/// Signing identity attached to the generated key.
const USER_ID: &str = "NORA repository signing";

pub struct RepoSigner {
    key: SignedSecretKey,
    public_armored: String,
    fingerprint: String,
}

impl RepoSigner {
    /// Load the signing key from `path`, or generate and persist one on
    /// first boot. Fail-closed: any error other than "file absent" is
    /// returned, never papered over with a fresh key — silently rotating
    /// the key would invalidate every client's pinned public key.
    pub fn load_or_generate(path: &Path) -> Result<Self, String> {
        let key = match std::fs::read_to_string(path) {
            Ok(armored) => {
                let (key, _) = SignedSecretKey::from_armor_single(Cursor::new(armored))
                    .map_err(|e| format!("parse signing key {}: {e}", path.display()))?;
                key
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = generate_key()?;
                persist_key(&key, path)?;
                tracing::info!(path = %path.display(), "generated new repository signing key");
                key
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
        })
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
/// parent directory. Written to a temp file then renamed, so a crash never
/// leaves a half-written key that would fail to parse on the next boot.
fn persist_key(key: &SignedSecretKey, path: &Path) -> Result<(), String> {
    let armored = key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| format!("armor signing key: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension("key.tmp");
    std::fs::write(&tmp, &armored).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
    Ok(())
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
