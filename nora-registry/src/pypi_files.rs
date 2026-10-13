//! PyPI distribution file names: which ones NORA serves, and the version a client reads from
//! one. Defined once here, for the server and for the fuzz targets alike.

use crate::validation::ends_with_ci;

/// The archive extensions NORA serves for PyPI, in any case: the ones pip installs that
/// PyPI accepts (`.tar.gz`, `.zip`, `.whl`, and `.tgz`), and `.egg` for the installers that
/// still read eggs. pip's other archive formats are neither listed nor served.
pub const SERVED_EXTENSIONS: [&str; 5] = [".tar.gz", ".tgz", ".zip", ".whl", ".egg"];

/// The served extension a file name ends with, in any case.
pub fn served_extension(filename: &str) -> Option<&'static str> {
    SERVED_EXTENSIONS
        .iter()
        .copied()
        .find(|ext| ends_with_ci(filename, ext))
}

/// A project name per PEP 503: lowercase, every run of `-`, `_` and `.` one `-`.
pub fn pep503_normalize(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut in_separator_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator_run {
                normalized.push('-');
            }
            in_separator_run = true;
        } else {
            normalized.extend(c.to_lowercase());
            in_separator_run = false;
        }
    }
    normalized
}

/// The version of project `normalized_name` (PEP 503) a client reads from a file NORA serves,
/// as pip reads it (`LinkEvaluator.evaluate_link`): a wheel names the project in its first
/// `-` field and the version in its second, and so does an egg (setuptools); an sdist is
/// `<name>-<version>` where the name may be spelled as published or escaped, so the version
/// follows the first `-` before which the name normalizes to the project's, without a
/// trailing Python tag (`-py3.8`, which pip takes off). An extension in another case is read
/// as in lowercase. `None` for a file NORA does not serve, another project's file, or an
/// empty version.
pub fn parse_pypi_version(normalized_name: &str, filename: &str) -> Option<String> {
    let ext = served_extension(filename)?;
    let base = filename[..filename.len() - ext.len()].to_lowercase();
    let version = if ext == ".whl" || ext == ".egg" {
        let mut fields = base.split('-');
        let name = fields.next()?;
        let version = fields.next()?;
        (pep503_normalize(name) == normalized_name).then_some(version)?
    } else {
        let rest = base
            .match_indices('-')
            .find(|&(i, _)| pep503_normalize(&base[..i]) == normalized_name)
            .map(|(i, _)| &base[i + 1..])?;
        without_python_tag(rest)
    };
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

/// A version without the Python tag pip takes off an sdist's (`_py_version_re`:
/// `-py([123]\.?[0-9]?)$`).
fn without_python_tag(version: &str) -> &str {
    let Some(at) = version.rfind("-py") else {
        return version;
    };
    let tag = &version.as_bytes()[at + 3..];
    let python = match tag {
        [major] | [major, b'.'] => matches!(major, b'1'..=b'3'),
        [major, minor] | [major, b'.', minor] => {
            matches!(major, b'1'..=b'3') && minor.is_ascii_digit()
        }
        _ => false,
    };
    if python {
        &version[..at]
    } else {
        version
    }
}
