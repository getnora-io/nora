//! The UI storage boundary in `clippy.toml` names the `Storage` methods that are not reads. A
//! method added to `Storage` and to neither side would be callable from the UI unseen, so every
//! method of every `impl Storage` that is visible outside its module is either a read listed
//! here and in the `clippy.toml` comment, or on `disallowed-methods`, and never both.

use std::collections::BTreeSet;
use std::path::Path;

/// The reads, as the `clippy.toml` comment names them.
const READS: &[&str] = &[
    "get",
    "get_pinned",
    "get_verified",
    "get_reader",
    "get_range",
    "list",
    "list_internal",
    "list_with_meta",
    "stat",
    "total_size",
    "backend_name",
    "pin",
    "recorded",
];

fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && a.parse_args::<syn::Meta>()
                .map(|m| m.path().is_ident("test"))
                .unwrap_or(false)
    })
}

/// The methods of `impl Storage` (no trait) visible outside their module, in `items` and the
/// inline modules inside them.
fn storage_methods(items: &[syn::Item], out: &mut BTreeSet<String>) {
    for item in items {
        match item {
            syn::Item::Impl(imp) if imp.trait_.is_none() && !is_test_only(&imp.attrs) => {
                let syn::Type::Path(ty) = &*imp.self_ty else {
                    continue;
                };
                if ty.path.segments.last().map(|s| s.ident == "Storage") != Some(true) {
                    continue;
                }
                for it in &imp.items {
                    if let syn::ImplItem::Fn(f) = it {
                        if !matches!(f.vis, syn::Visibility::Inherited) && !is_test_only(&f.attrs) {
                            out.insert(f.sig.ident.to_string());
                        }
                    }
                }
            }
            syn::Item::Mod(m) if !is_test_only(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    storage_methods(inner, out);
                }
            }
            _ => {}
        }
    }
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_storage_method_is_a_listed_read_or_on_the_ui_deny_list() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut methods = BTreeSet::new();
    for file in &files {
        let source = std::fs::read_to_string(file).unwrap();
        let parsed = syn::parse_file(&source).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        storage_methods(&parsed.items, &mut methods);
    }
    assert!(
        methods.contains("put") && methods.contains("get"),
        "{methods:?}"
    );

    let clippy = std::fs::read_to_string(root.join("../clippy.toml")).unwrap();
    let table: toml::Table = clippy.parse().unwrap();
    let denied: BTreeSet<String> = table["disallowed-methods"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("path")?.as_str())
        .filter_map(|p| p.strip_prefix("nora::storage::Storage::"))
        .map(str::to_string)
        .collect();
    let reads: BTreeSet<String> = READS.iter().map(|s| s.to_string()).collect();

    let unlisted: Vec<_> = methods
        .iter()
        .filter(|m| !reads.contains(*m) && !denied.contains(*m))
        .collect();
    assert!(
        unlisted.is_empty(),
        "Storage methods on neither side of the UI boundary: {unlisted:?}. A write goes on \
         disallowed-methods in clippy.toml; a read goes on READS here and in the clippy.toml comment"
    );
    let both: Vec<_> = reads.intersection(&denied).collect();
    assert!(both.is_empty(), "listed as a read and denied: {both:?}");
    let stale: Vec<_> = reads
        .union(&denied)
        .filter(|m| !methods.contains(*m))
        .collect();
    assert!(
        stale.is_empty(),
        "listed but not a Storage method: {stale:?}"
    );

    // The comment in clippy.toml names the same reads.
    let comment: String = clippy
        .lines()
        .filter_map(|l| l.strip_prefix('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let start = comment
        .find("that are not reads")
        .expect("reads named in clippy.toml");
    let open = start + comment[start..].find('(').unwrap() + 1;
    let close = open + comment[open..].find(')').unwrap();
    let in_comment: BTreeSet<String> = comment[open..close]
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    assert_eq!(
        in_comment, reads,
        "the clippy.toml comment names other reads"
    );
}
