# What ansible-galaxy builds and sends to a Galaxy server at NORA's mount (`<server>/ansible/`).
# Each collection is built by `ansible-galaxy collection build` from a galaxy.yml (the artifact
# file name is the tool's); an in-process HTTP server answers as NORA does (API root with
# `{"v3": "v3/"}`, short v3 paths, `download_url` under `/ansible/download/`) and logs every
# request as the client wrote it; then `ansible-galaxy collection install` and `download` of each
# built collection run against it. One row per line: kind (`build` or the command), namespace,
# name, version, then the artifact file name (build; BUILD-ERROR when the tool refuses) or the
# method and path of a request.
import hashlib, http.server, json, os, re, shutil, subprocess, tempfile, threading
from ansible.release import __version__ as ansible_version

COLLECTIONS = [
    ("community", "general", "10.1.0"), ("my_ns", "my_coll", "1.0.0-beta.1"),
    ("acme", "tools", "2.0.0+build.7"), ("ns1", "c_2", "0.1.0-rc.1+sha.5114f85"),
    ("a", "b", "1.0.0"), ("ns", "x", "1.0.0-0.3.7"), ("ns", "y", "1.0.0-x-y-z.1"),
    ("Upper", "Coll", "1.0.0"), ("ns", "z", "01.0.0"), ("ns", "w", "1.0"), ("ns", "v", "v1.0.0"),
    ("ns", "u", "1.0.0-01"), ("ns", "t", "1.0.0+01"), ("ns", "s", "1.0.0_1"),
    ("n__s", "dunder", "1.0.0"), ("_ns", "lead", "1.0.0"), ("ns", "if", "1.0.0"),
]

work = tempfile.mkdtemp()
built = {}  # (ns, name, ver) -> file name
rows = []
for ns, name, ver in COLLECTIONS:
    src = os.path.join(work, "src", f"{ns}_{name}")
    os.makedirs(src)
    with open(os.path.join(src, "galaxy.yml"), "w") as f:
        f.write(f"namespace: {ns}\nname: {name}\nversion: '{ver}'\nreadme: README.md\nauthors: [x]\n")
    open(os.path.join(src, "README.md"), "w").close()
    out = os.path.join(work, "out")
    os.makedirs(out, exist_ok=True)
    before = set(os.listdir(out))
    r = subprocess.run(["ansible-galaxy", "collection", "build", src, "--output-path", out],
                       capture_output=True, text=True)
    new = sorted(set(os.listdir(out)) - before)
    if r.returncode == 0 and len(new) == 1:
        built[(ns, name, ver)] = new[0]
        rows.append(("build", ns, name, ver, new[0]))
    else:
        rows.append(("build", ns, name, ver, "BUILD-ERROR"))


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


artifacts = {fn: read_bytes(os.path.join(work, "out", fn)) for fn in built.values()}
current = {"kind": "", "ns": "", "name": "", "ver": ""}
base = ""


def answer(path):
    if path in ("/ansible/", "/ansible/api/"):
        return {"available_versions": {"v3": "v3/"}}
    m = re.fullmatch(r"/ansible/v3/collections/([^/]+)/([^/]+)/(?:versions/(?:([^/]+)/)?)?", path)
    if m:
        ns, name, ver = m.groups()
        mine = [(k, fn) for k, fn in built.items() if k[0] == ns and k[1] == name]
        if not mine:
            return None
        href = f"/ansible/v3/collections/{ns}/{name}/"
        if not path.endswith("/versions/") and ver is None:
            return {"namespace": ns, "name": name, "href": href, "updated_at": "2026-10-12T00:00:00Z",
                    "highest_version": {"version": mine[0][0][2]}}
        if ver is None:
            return {"meta": {"count": len(mine)}, "links": {"next": None},
                    "data": [{"version": k[2], "href": f"{href}versions/{k[2]}/"} for k, _ in mine]}
        for k, fn in mine:
            if k[2] == ver:
                return {"namespace": {"name": ns}, "collection": {"name": name}, "version": ver,
                        "href": f"{href}versions/{ver}/", "download_url": f"{base}/ansible/download/{fn}",
                        "artifact": {"filename": fn, "sha256": hashlib.sha256(artifacts[fn]).hexdigest(),
                                     "size": len(artifacts[fn])},
                        "metadata": {"dependencies": {}}, "signatures": []}
        return None
    m = re.fullmatch(r"/ansible/download/([^/]+)", path)
    if m and m.group(1) in artifacts:
        return artifacts[m.group(1)]
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        rows.append((current["kind"], current["ns"], current["name"], current["ver"], f"GET {self.path}"))
        body = answer(self.path.partition("?")[0])
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        ctype = "application/octet-stream" if isinstance(body, bytes) else "application/json"
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{server.server_port}"
env = dict(os.environ, ANSIBLE_GALAXY_DISABLE_GPG_VERIFY="1", ANSIBLE_GALAXY_CACHE_DIR=os.path.join(work, "cache"))
for (ns, name, ver) in built:
    for command in ("install", "download"):
        dest = os.path.join(work, command)
        shutil.rmtree(dest, ignore_errors=True)
        current.update(kind=command, ns=ns, name=name, ver=ver)
        args = ["ansible-galaxy", "collection", command, f"{ns}.{name}:=={ver}", "-s", f"{base}/ansible/",
                "--no-cache", "-p" if command == "install" else "--download-path", dest]
        r = subprocess.run(args, capture_output=True, text=True, env=env)
        if r.returncode != 0:
            rows.append((command, ns, name, ver, "CLIENT-ERROR " + (r.stdout + r.stderr).strip().splitlines()[-1]))
server.shutdown()

print("# Regenerate: docker run --rm -v \"$PWD/nora-registry/testdata/ansible:/w:ro\" python:3.13-slim sh -c "
      f"'pip install -q \"ansible-core=={ansible_version}\" 2>/dev/null; python /w/client_requests.py' > nora-registry/testdata/ansible/client-requests.tsv")
print(f"# ansible-core {ansible_version} (python:3.13-slim), server http://127.0.0.1:<port>/ansible/")
print("# kind\tnamespace\tname\tversion\tartifact file name, or request (method path)")
for row in rows:
    print("\t".join(row))
