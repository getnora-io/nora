# What the Conan 2 client sends to a remote at NORA's mount (`<server>/conan`). Recipes and
# packages are built by `conan create` and uploaded by `conan upload` to an in-process HTTP server
# that keeps what it is sent and logs every request as the client wrote it; a second, empty Conan
# home then runs `conan install`, `conan download` and `conan list` against it. One row per
# request: command, reference, method, path (with query). Revisions are content hashes of what
# Conan exported, so they repeat from run to run.
import fnmatch, http.server, json, os, re, subprocess, sys, tempfile, threading
from urllib.parse import unquote
from conan import __version__ as conan_version

REFS = ["zlib/1.2.13", "zlib/1.2.13@acme/stable", "fmt/10.2.1", "openssl/3.0.13",
        "pkg_a/1.0.0-rc.1+build.7", "dots.and+plus/1.0", "under_score/0.1@my-user/test.channel",
        "boost/1.84.0", "v-pkg/v1.2", "date/2024.01.01", "aa/1.0.0+b", "zz/1.0.0",
        "Upper/1.0@User/Chan"]

work = tempfile.mkdtemp()
build_home, client_home = os.path.join(work, "build"), os.path.join(work, "client")


def conan(*args, home=build_home, check=True):
    r = subprocess.run(["conan", *args], env=dict(os.environ, CONAN_HOME=home),
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"conan {' '.join(args)} failed")
    return r


files = {}  # path under /conan/v2/conans -> bytes, as uploaded
log = []
current = {"command": "", "ref": ""}
WHEN = "2026-10-12T00:00:00.000+0000"


def children(prefix):
    """Distinct next path segments under `prefix/` among uploaded files."""
    out = []
    for p in files:
        if p.startswith(prefix + "/"):
            seg = p[len(prefix) + 1:].split("/", 1)[0]
            if seg not in out:
                out.append(seg)
    return out


def ref_of(base):
    name, version, user, channel = base.split("/")[4:8]
    return f"{name}/{version}" + (f"@{user}/{channel}" if user != "_" else "")


def answer(path, query):
    m = re.fullmatch(r"(/conan/v2/conans/[^/]+/[^/]+/[^/]+/[^/]+)(/.*)?", path)
    if path == "/conan/v2/conans/search":
        q = unquote(query.split("q=", 1)[1]) if "q=" in query else "*"
        refs = sorted({ref_of(p[:p.index("/revisions")]) for p in files})
        return {"results": [r for r in refs if fnmatch.fnmatchcase(r, q)]}
    if path in ("/conan/v2/users/authenticate",):
        return "token"
    if path == "/conan/v2/users/check_credentials":
        return "user"
    if not m:
        return None
    base, rest = m.group(1), m.group(2) or ""
    revisions = [{"revision": r, "time": WHEN} for r in children(base + "/revisions")]
    if rest == "/latest":
        return revisions[-1] if revisions else None
    if rest == "/revisions":
        return {"reference": ref_of(base), "revisions": revisions} if revisions else None
    m = re.fullmatch(r"/revisions/([^/]+)(/.*)", rest)
    if not m:
        return None
    rrev, rest = m.groups()
    rbase = f"{base}/revisions/{rrev}"
    if rest == "/files":
        names = [p[len(rbase) + 7:] for p in files if p.startswith(rbase + "/files/")]
        return {"files": {n: {} for n in names}} if names else None
    if rest.startswith("/files/"):
        return files.get(path)
    if rest == "/search":
        return {pid: {"settings": {}, "options": {}, "requires": []} for pid in children(rbase + "/packages")}
    m = re.fullmatch(r"/packages/([^/]+)(/.*)", rest)
    if not m:
        return None
    pid, rest = m.groups()
    pbase = f"{rbase}/packages/{pid}"
    prevs = [{"revision": r, "time": WHEN} for r in children(pbase + "/revisions")]
    if rest == "/latest":
        return prevs[-1] if prevs else None
    if rest == "/revisions":
        return {"reference": f"{ref_of(base)}#{rrev}:{pid}", "revisions": prevs} if prevs else None
    m = re.fullmatch(r"/revisions/([^/]+)/files", rest)
    if m:
        pr = f"{pbase}/revisions/{m.group(1)}/files/"
        names = [p[len(pr):] for p in files if p.startswith(pr)]
        return {"files": {n: {} for n in names}} if names else None
    return files.get(path)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, body):
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if isinstance(body, bytes):
            ctype = "application/octet-stream"
        elif isinstance(body, str):
            body, ctype = body.encode(), "text/plain"
        else:
            body, ctype = json.dumps(body).encode(), "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        log.append((current["command"], current["ref"], "GET", self.path))
        path, _, query = self.path.partition("?")
        if path in ("/conan/v1/ping", "/conan/v2/ping"):
            self.send_response(200)
            self.send_header("X-Conan-Server-Capabilities", "revisions")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.reply(answer(path, query))

    def do_HEAD(self):
        log.append((current["command"], current["ref"], "HEAD", self.path))
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        log.append((current["command"], current["ref"], "PUT", self.path))
        n = int(self.headers.get("Content-Length", 0))
        files[self.path.partition("?")[0]] = self.rfile.read(n)
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{server.server_port}/conan"
for home in (build_home, client_home):
    conan("profile", "detect", home=home)
    with open(os.path.join(home, "global.conf"), "a") as f:
        f.write("core:allow_uppercase_pkg_names=True\n")
    conan("remote", "remove", "conancenter", home=home)
    conan("remote", "add", "nora", url, home=home)
conan("remote", "login", "nora", "user", "-p", "pass")

for ref in REFS:
    nv, _, uc = ref.partition("@")
    name, version = nv.split("/", 1)
    user, _, channel = uc.partition("/")
    d = os.path.join(work, "src", re.sub(r"[^a-zA-Z0-9]", "_", ref))
    os.makedirs(d)
    with open(os.path.join(d, "conanfile.py"), "w") as f:
        f.write("from conan import ConanFile\n\nclass P(ConanFile):\n    pass\n")
    args = ["create", d, "--name", name, "--version", version]
    if user:
        args += ["--user", user, "--channel", channel]
    conan(*args)
    current.update(command="upload", ref=ref)
    conan("upload", ref, "-r", "nora", "-c")

for ref in REFS:
    for command, pattern in (("install", None), ("download", ref), ("download", f"{ref}:*"),
                             ("list", f"{ref}#*:*")):
        conan("remove", "*", "-c", home=client_home, check=False)
        current.update(command=f"{command} {pattern}" if pattern else command, ref=ref)
        if command == "install":
            conan("install", f"--requires={ref}", "-r", "nora", home=client_home)
        else:
            conan(command, pattern, "-r", "nora", home=client_home)
current.update(command="list z*", ref="")
conan("list", "z*", "-r", "nora", home=client_home)
server.shutdown()

print("# Regenerate: docker run --rm -v \"$PWD/nora-registry/testdata/conan:/w:ro\" python:3.13-slim sh -c "
      f"'pip install -q \"conan=={conan_version}\" 2>/dev/null; python /w/client_requests.py' > nora-registry/testdata/conan/client-requests.tsv")
print(f"# Conan {conan_version} (python:3.13-slim), remote http://127.0.0.1:<port>/conan")
print("# command\treference\tmethod\tpath")
for row in log:
    print("\t".join(row))
