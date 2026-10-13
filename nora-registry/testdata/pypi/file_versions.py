# Regenerate: docker run --rm -v "$PWD/nora-registry/testdata/pypi:/w:ro" python:3.13-slim sh -c 'pip install --quiet --root-user-action=ignore setuptools==80.9.0 && python /w/file_versions.py' > nora-registry/testdata/pypi/file-versions.tsv
# Which version a client that takes a distribution file reads from its name. pip decides with
# its own LinkEvaluator.evaluate_link (run here as is): a wheel's version from its name, any other
# archive's after the first `-` whose prefix canonicalizes to the project, a trailing Python tag
# (`-py3.8`) taken off, and an extension pip does not support (in any other case, `.egg`)
# skipped. An `.egg` is read by setuptools (pkg_resources.Distribution.from_filename). A file
# whose extension pip skips only for its case is read as pip reads it in lowercase.
# One row per file: project, file name, how it is read (pip's result, `egg`, `case`), the version
# read (empty: none) and its PEP 440 canonical form (empty: not a PEP 440 version).
import re
import urllib.parse
import warnings

warnings.filterwarnings("ignore")
import pip
import setuptools
from pip._vendor import packaging
from pip._vendor.packaging.utils import canonicalize_name
from pip._vendor.packaging.version import Version, InvalidVersion
from pip._internal.index.package_finder import LinkEvaluator, SUPPORTED_EXTENSIONS
from pip._internal.models.link import Link
from pip._internal.models.target_python import TargetPython
from pkg_resources import Distribution

projects = ["Flask", "Flask_RESTful", "zope.interface", "python-dateutil", "a-b-c", "foo.-_bar", "A1",
            "FlasK"]
versions = ["1.0", "1.0.0", "1.0.0rc1", "1.0.0.RC1", "1.0.0-rc1", "1.0.0c1", "1.0.0_rc_1", "1.0.post1",
            "1.0-1", "1.0.dev0", "v1.0", "V1.0", "1.0+local.7", "1.0+Local-7", "1.0a1", "1.0ALPHA1",
            "1.0.0.0", "01.02", "1!2.0", "2004b", "1.0-beta-1", "1.0.0-final", "1.0rev3", ""]
sdist_exts = [ext for ext in SUPPORTED_EXTENSIONS if ext != ".whl"] + [".TAR.GZ", ".Zip", ".TGZ"]


def escaped(project):  # binary distribution format: runs of -_. become _, lowercase
    return canonicalize_name(project).replace("-", "_")


def evaluate(project, filename):
    """pip's LinkEvaluator on the file; a Python-tag mismatch is retried with that Python."""
    canonical = canonicalize_name(project)
    url = "https://files.example/packages/" + urllib.parse.quote(filename)
    target = TargetPython()
    for _ in range(2):
        evaluator = LinkEvaluator(project_name=project, canonical_name=canonical,
                                  formats=frozenset({"binary", "source"}), target_python=target,
                                  allow_yanked=True, ignore_requires_python=True)
        kind, detail = evaluator.evaluate_link(Link(url))
        if kind.name == "platform_mismatch" and detail == "Python version is incorrect":
            tag = re.search(r"-py(\d)\.?(\d)$", filename.rsplit(".", 2)[0].split(".tar")[0])
            if tag:
                target = TargetPython(py_version_info=(int(tag.group(1)), int(tag.group(2))))
                continue
        break
    return kind.name, (detail if kind.name == "candidate" else "")


def reads(project, filename):
    if filename.endswith(".egg"):
        dist = Distribution.from_filename(filename)
        if canonicalize_name(dist.project_name) != canonicalize_name(project):
            return "egg", ""
        return "egg", str(dist._version) if dist._version else ""
    kind, version = evaluate(project, filename)
    if kind == "format_unsupported":
        for ext in SUPPORTED_EXTENSIONS:
            if filename.lower().endswith(ext) and not filename.endswith(ext):
                _, lower = evaluate(project, filename[: -len(ext)] + ext)
                return "case", lower
    return kind, version


def canonical(version):
    try:
        return str(Version(version))
    except InvalidVersion:
        return None


rows = set()
for p in projects:
    for v in versions:
        for name in {p, escaped(p), p.lower(), canonicalize_name(p)}:
            for ext in sdist_exts:
                rows.add((p, f"{name}-{v}{ext}"))
        if v and "-" not in v:
            rows.add((p, f"{name}-{v}-py3.8.tar.gz"))
            rows.add((p, f"{escaped(p)}-{v}-py3-none-any.whl"))
            rows.add((p, f"{p}-{v}-py2.py3-none-any.whl"))
            rows.add((p, f"{escaped(p)}-{v}-py3.8.egg"))
            rows.add((p, f"{escaped(p)}-{v}.egg"))
            rows.add((p, f"{escaped(p)}-{v}-py3.8-linux-x86_64.egg"))
    rows.add((p, "django-1.0-py3-none-any.whl"))
    rows.add((p, f"{escaped(p)}x-1.0.tar.gz"))
print(f"# pip {pip.__version__}, packaging {packaging.__version__}, setuptools {setuptools.__version__}")
for p, f in sorted(rows):
    kind, v = reads(p, f)
    c = canonical(v) if v else None
    print("\t".join([p, f, kind, v or "", c or ""]))
