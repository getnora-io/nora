// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! What `nora import` does with an artifact from what already lies under the key it built, before
//! anything is downloaded. One rule, [`action`], for every format: a format without a decision
//! does not compile, and the import looks under a key only through [`under_key`].

use crate::registry_type::RegistryType;
use crate::storage::Storage;

/// What lies under an artifact's key, as far as the import looked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnderKey {
    /// The import did not look: on S3 a look is a request per object (review R5).
    NotLooked,
    /// Nothing.
    Nothing,
    /// An object, and the record the format writes after it once the object is NORA's own
    /// ([`record_key`]).
    Recorded,
    /// An object without such a record: what an import stored before its record was written,
    /// what an upstream served under the name, or an object of a format without a record. Which
    /// one, the import cannot tell.
    Unrecorded,
}

/// What the import does with an artifact before any transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Action {
    /// Transfer the source's artifact: download, verify, curate, and commit it with every record
    /// its format keeps beside it.
    Transfer,
    /// Leave what is there; the journal records the key.
    Skip,
}

/// What the import does with an artifact of format `rt` when `under` lies under its key.
///
/// - Maven and Raw keep no record: whatever is under the key is served as it is, so the import
///   leaves it. Raw has no upstream; a Maven coordinate is served from storage before any
///   upstream, whoever stored it.
/// - npm: a tarball whose version document is there is published, and is left. One without it
///   may be what an upstream served under the name, and publishing it would make the upstream's
///   bytes the imported version: the source's tarball is transferred, and its document written.
/// - PyPI and NuGet: what is under the key may be what an upstream served before the import made
///   the name NORA's own, and only a transfer stores the source's verified bytes and writes every
///   record beside them.
/// - The other formats are not imported ([`super::layout::map_artifact`] skips them first).
pub(super) fn action(rt: RegistryType, under: UnderKey) -> Action {
    use Action::{Skip, Transfer};
    use UnderKey::{NotLooked, Nothing, Recorded, Unrecorded};
    match rt {
        RegistryType::Maven | RegistryType::Raw => match under {
            NotLooked | Nothing => Transfer,
            Recorded | Unrecorded => Skip,
        },
        RegistryType::Npm => match under {
            NotLooked | Nothing | Unrecorded => Transfer,
            Recorded => Skip,
        },
        RegistryType::PyPI | RegistryType::Nuget => Transfer,
        RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => Transfer,
    }
}

/// The record that makes the object at `key` of format `rt` NORA's own, written after the object:
/// an npm tarball's version document. The formats [`action`] does not skip by a record have none
/// here.
fn record_key(rt: RegistryType, key: &str) -> Option<String> {
    match rt {
        RegistryType::Npm => crate::registry::npm::imported_version_key(key),
        RegistryType::Maven
        | RegistryType::Raw
        | RegistryType::PyPI
        | RegistryType::Nuget
        | RegistryType::Docker
        | RegistryType::Cargo
        | RegistryType::Go
        | RegistryType::Gems
        | RegistryType::Terraform
        | RegistryType::Ansible
        | RegistryType::PubDart
        | RegistryType::Conan
        | RegistryType::Rpm
        | RegistryType::Deb
        | RegistryType::Cpan
        | RegistryType::HuggingFace => None,
    }
}

/// What lies under `key` of format `rt`: not looked at on S3, else the object and its record.
/// The only place the import looks at storage before a transfer.
pub(super) async fn under_key(
    storage: &Storage,
    rt: RegistryType,
    on_s3: bool,
    key: &str,
) -> UnderKey {
    if on_s3 {
        return UnderKey::NotLooked;
    }
    if storage.stat(key).await.is_none() {
        return UnderKey::Nothing;
    }
    match record_key(rt, key) {
        Some(record) if storage.stat(&record).await.is_some() => UnderKey::Recorded,
        _ => UnderKey::Unrecorded,
    }
}

#[cfg(test)]
mod tests {
    use super::{action, record_key, Action, UnderKey};
    use crate::registry_type::RegistryType;
    use std::path::{Path, PathBuf};

    /// Every format against every state of its key: what the import does. `upstream cache` is
    /// an object without a record, which is how an upstream's copy of the same version lies.
    #[test]
    fn what_the_import_does_with_what_lies_under_the_key() {
        use Action::{Skip, Transfer};
        use RegistryType as R;
        //            not looked (S3)  nothing    recorded   upstream cache / unrecorded
        let table: &[(RegistryType, [Action; 4])] = &[
            (R::Docker, [Transfer, Transfer, Transfer, Transfer]),
            (R::Maven, [Transfer, Transfer, Skip, Skip]),
            (R::Npm, [Transfer, Transfer, Skip, Transfer]),
            (R::Cargo, [Transfer, Transfer, Transfer, Transfer]),
            (R::PyPI, [Transfer, Transfer, Transfer, Transfer]),
            (R::Go, [Transfer, Transfer, Transfer, Transfer]),
            (R::Raw, [Transfer, Transfer, Skip, Skip]),
            (R::Gems, [Transfer, Transfer, Transfer, Transfer]),
            (R::Terraform, [Transfer, Transfer, Transfer, Transfer]),
            (R::Ansible, [Transfer, Transfer, Transfer, Transfer]),
            (R::Nuget, [Transfer, Transfer, Transfer, Transfer]),
            (R::PubDart, [Transfer, Transfer, Transfer, Transfer]),
            (R::Conan, [Transfer, Transfer, Transfer, Transfer]),
            (R::Rpm, [Transfer, Transfer, Transfer, Transfer]),
            (R::Deb, [Transfer, Transfer, Transfer, Transfer]),
            (R::Cpan, [Transfer, Transfer, Transfer, Transfer]),
            (R::HuggingFace, [Transfer, Transfer, Transfer, Transfer]),
        ];
        let states = [
            UnderKey::NotLooked,
            UnderKey::Nothing,
            UnderKey::Recorded,
            UnderKey::Unrecorded,
        ];
        for (rt, row) in table {
            for (under, want) in states.into_iter().zip(row) {
                assert_eq!(action(*rt, under), *want, "{rt:?} with {under:?}");
            }
        }
        let rows: Vec<RegistryType> = table.iter().map(|(rt, _)| *rt).collect();
        assert_eq!(rows, RegistryType::all(), "a row for every format");
    }

    /// What the import sees under a key: nothing looked at on S3, else the object and, for npm,
    /// its version document.
    #[tokio::test]
    async fn what_lies_under_a_key_is_looked_at_on_local_storage_only() {
        use super::under_key;
        let root = tempfile::tempdir().unwrap();
        let storage = crate::storage::Storage::new_local(root.path().to_str().unwrap());
        let (jar, tgz) = ("maven/com/a/1.0/a-1.0.jar", "npm/a/tarballs/a-1.0.0.tgz");
        assert_eq!(
            under_key(&storage, RegistryType::Maven, false, jar).await,
            UnderKey::Nothing
        );
        storage.put(jar, b"jar").await.unwrap();
        storage.put(tgz, b"tgz").await.unwrap();
        assert_eq!(
            under_key(&storage, RegistryType::Maven, true, jar).await,
            UnderKey::NotLooked
        );
        assert_eq!(
            under_key(&storage, RegistryType::Maven, false, jar).await,
            UnderKey::Unrecorded
        );
        assert_eq!(
            under_key(&storage, RegistryType::Npm, false, tgz).await,
            UnderKey::Unrecorded
        );
        storage
            .put("npm/a/versions/1.0.0.json", b"{}")
            .await
            .unwrap();
        assert_eq!(
            under_key(&storage, RegistryType::Npm, false, tgz).await,
            UnderKey::Recorded
        );
        assert_eq!(
            under_key(&storage, RegistryType::Npm, true, tgz).await,
            UnderKey::NotLooked
        );
    }

    /// An npm tarball's record is its version document; no other format is skipped by one.
    #[test]
    fn only_an_npm_tarball_is_told_by_its_record() {
        assert_eq!(
            record_key(RegistryType::Npm, "npm/@scope/a/tarballs/a-1.0.0.tgz").as_deref(),
            Some("npm/@scope/a/versions/1.0.0.json")
        );
        for rt in RegistryType::all() {
            if *rt != RegistryType::Npm {
                assert_eq!(
                    record_key(*rt, "npm/a/tarballs/a-1.0.0.tgz"),
                    None,
                    "{rt:?}"
                );
            }
        }
    }

    /// The reads of [`crate::storage::Storage`] whose names nothing else in the import uses.
    /// `get` is also a map's and a client's: it counts when called on a `storage`.
    const READS: [&str; 7] = [
        "stat",
        "list",
        "list_internal",
        "list_with_meta",
        "get_verified",
        "get_reader",
        "get_range",
    ];

    /// Where the sources of the import read storage outside the items under `#[cfg(test)]`:
    /// `file: function` for each read.
    #[derive(Default)]
    struct Looks {
        file: String,
        function: Vec<String>,
        found: Vec<String>,
    }

    fn under_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|a| {
            a.path().is_ident("cfg")
                && matches!(&a.meta, syn::Meta::List(l)
                    if l.tokens.to_string().split_whitespace().collect::<String>() == "test")
        })
    }

    /// Whether `expr` names a storage: `storage`, `x.storage`, through `&` and parentheses.
    fn is_storage(expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(p) => p.path.is_ident("storage"),
            syn::Expr::Field(f) => matches!(&f.member, syn::Member::Named(m) if m == "storage"),
            syn::Expr::Reference(r) => is_storage(&r.expr),
            syn::Expr::Paren(p) => is_storage(&p.expr),
            _ => false,
        }
    }

    impl Looks {
        fn read(file: &str, text: &str) -> Vec<String> {
            let parsed = syn::parse_file(text).unwrap();
            let mut looks = Self {
                file: file.to_owned(),
                ..Self::default()
            };
            if !under_test(&parsed.attrs) {
                syn::visit::Visit::visit_file(&mut looks, &parsed);
            }
            looks.found
        }

        fn look(&mut self) {
            let function = self.function.last().cloned().unwrap_or_default();
            self.found.push(format!("{}: {function}", self.file));
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for Looks {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let attrs: &[syn::Attribute] = match item {
                syn::Item::Mod(m) => &m.attrs,
                syn::Item::Fn(f) => &f.attrs,
                syn::Item::Impl(i) => &i.attrs,
                syn::Item::Trait(t) => &t.attrs,
                syn::Item::Const(c) => &c.attrs,
                syn::Item::Static(s) => &s.attrs,
                _ => &[],
            };
            if under_test(attrs) {
                return;
            }
            if let syn::Item::Fn(f) = item {
                self.function.push(f.sig.ident.to_string());
                syn::visit::visit_item(self, item);
                self.function.pop();
                return;
            }
            syn::visit::visit_item(self, item);
        }

        fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
            if under_test(&f.attrs) {
                return;
            }
            self.function.push(f.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, f);
            self.function.pop();
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            let name = call.method.to_string();
            if READS.contains(&name.as_str()) || (name == "get" && is_storage(&call.receiver)) {
                self.look();
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            // `Storage::stat(&storage, key)`, `Storage::get`, called or passed as a function.
            let names: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if let [.., ty, read] = names.as_slice() {
                if ty == "Storage" && (READS.contains(&read.as_str()) || read == "get") {
                    self.look();
                }
            }
            syn::visit::visit_expr_path(self, path);
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            // A call inside a macro's tokens is not parsed as an expression: a method call of a
            // read there counts as one.
            let tokens: Vec<String> = mac
                .tokens
                .to_string()
                .split_whitespace()
                .map(str::to_owned)
                .collect();
            if tokens
                .windows(2)
                .any(|w| w[0] == "." && READS.contains(&w[1].as_str()))
                || tokens
                    .windows(3)
                    .any(|w| w[0] == "storage" && w[1] == "." && w[2] == "get")
            {
                self.look();
            }
        }
    }

    fn import_sources() -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/import"),
            &mut files,
        );
        files.sort();
        files
    }

    /// The import reads storage only through [`super::under_key`]: no other function of
    /// `src/import/` looks at a key, so no fast path decides without [`action`].
    #[test]
    fn the_import_looks_under_a_key_only_through_one_function() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/import");
        let mut found = Vec::new();
        for file in import_sources() {
            let name = file.strip_prefix(&root).unwrap().display().to_string();
            found.extend(Looks::read(&name, &std::fs::read_to_string(&file).unwrap()));
        }
        assert_eq!(
            found,
            ["under_key.rs: under_key", "under_key.rs: under_key"],
            "the storage reads of the import"
        );
    }

    /// Each way to stat a key elsewhere is found, in any spacing or over several lines; a stat
    /// in test code is not.
    #[test]
    fn every_way_to_look_elsewhere_is_found() {
        let fine = Looks::read(
            "x.rs",
            "fn f() {}\n#[cfg(test)]\nmod tests { async fn t(s: &S) { s.stat(\"k\").await; } }\n#[cfg(test)]\nasync fn g(s: &S) { s.stat(\"k\").await; }",
        );
        assert!(fine.is_empty(), "{fine:?}");
        // A map's or a client's `get` is no storage read.
        let other = Looks::read(
            "x.rs",
            "async fn f(http: &H, v: &V) { http.get(\"/api\").await; v.get(\"layout\"); }",
        );
        assert!(other.is_empty(), "{other:?}");
        let named = Looks::read("x.rs", "fn f(list: &L) { format!(\"{}\", list.len()); }");
        assert!(named.is_empty(), "{named:?}");
        for (bad, at) in [
            ("async fn f(s: &S) { if s.stat(&key).await.is_some() {} }", "x.rs: f"),
            ("async fn f(s: &S) {\n    s\n        .stat(\n            &key,\n        )\n        .await;\n}", "x.rs: f"),
            ("impl R { async fn m(&self) { self.storage.stat(k).await; } }", "x.rs: m"),
            ("async fn f(s: &S) { let g = async { Storage::stat(s, k).await }; }", "x.rs: f"),
            ("async fn f(s: &S) { let l = keys.iter().map(|k| s.stat(k)); }", "x.rs: f"),
            ("fn f() { look!(storage.stat(k)); }", "x.rs: f"),
            ("async fn f(s: &S) { if storage.get(&key).await.is_ok() {} }", "x.rs: f"),
            ("async fn f(r: &R) { r.storage.get(&key).await; }", "x.rs: f"),
            ("async fn f(s: &S) { s.list(\"npm/a/\").await; }", "x.rs: f"),
            ("async fn f(s: &S) { s.list_with_meta(p).await; }", "x.rs: f"),
            ("async fn f(s: &S) { Storage::get(s, k).await; }", "x.rs: f"),
            ("fn f() { look!(storage . get(k)); }", "x.rs: f"),
        ] {
            assert_eq!(Looks::read("x.rs", bad), [at], "{bad}");
        }
    }
}
