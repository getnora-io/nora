# What cpanm sends to a CPAN mirror at NORA's mount (`<server>/cpan`). Distributions are built
# with tar/zip, listed in a generated 02packages.details.txt.gz under author directories, and
# served by an in-process HTTP server that logs every request as the client wrote it; cpanm then
# installs each module from the mirror (`--mirror <server>/cpan --mirror-only`), and each
# distribution by its author path. One row per request: what was installed, method, path.
import gzip, http.server, io, os, subprocess, tarfile, tempfile, threading, zipfile

DISTS = [  # author path, module
    ("A/AU/AUTHOR/Foo-Bar-1.23.tar.gz", "Foo::Bar"),
    ("A/AU/AUTHOR/Baz-Qux-v1.2.3.tgz", "Baz::Qux"),
    ("E/EX/EXAMPLE/CGI-Mini.pm-4.66.tar.gz", "CGI::Mini"),
    ("C/CH/CHAMAS/Crypt-Ecbx-1.1-2.tar.gz", "Crypt::Ecbx"),
    ("X/XY/XYZ-9/Quux-1.0.tar.bz2", "Quux"),
    ("Z/ZZ/ZZZ/Zip-Dist-0.01.zip", "Zip::Dist"),
    ("R/RC/RCAUTH/Rc-Dist-1.23-RC1.tar.gz", "Rc::Dist"),
]

work = tempfile.mkdtemp()
files = {}
for path, module in DISTS:
    fn = path.rsplit("/", 1)[1]
    for ext in (".tar.gz", ".tgz", ".tar.bz2", ".zip"):
        if fn.endswith(ext):
            top = fn[: -len(ext)]
    pm = module.split("::")
    version = "1.00"
    members = {
        f"{top}/Makefile.PL": "use ExtUtils::MakeMaker;\nWriteMakefile(NAME => '%s', VERSION => '%s');\n" % (module, version),
        f"{top}/lib/{'/'.join(pm)}.pm": "package %s;\nour $VERSION = '%s';\n1;\n" % (module, version),
    }
    buf = io.BytesIO()
    if fn.endswith(".zip"):
        with zipfile.ZipFile(buf, "w") as z:
            for name, text in members.items():
                z.writestr(name, text)
    else:
        mode = "w:bz2" if fn.endswith(".bz2") else "w:gz"
        with tarfile.open(fileobj=buf, mode=mode) as t:
            for name, text in members.items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
    files["/cpan/authors/id/" + path] = buf.getvalue()

lines = ["File:         02packages.details.txt", "Line-Count:   %d" % len(DISTS), ""]
lines += ["%-40s %-10s %s" % (module, "1.00", path) for path, module in DISTS]
files["/cpan/modules/02packages.details.txt.gz"] = gzip.compress(("\n".join(lines) + "\n").encode())

log = []
current = [""]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        log.append((current[0], "GET", self.path))
        body = files.get(self.path.partition("?")[0])
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Length", str(len(body or b"")))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self):
        log.append((current[0], "HEAD", self.path))
        body = files.get(self.path.partition("?")[0])
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Length", str(len(body or b"")))
        self.end_headers()


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
mirror = f"http://127.0.0.1:{server.server_port}/cpan"
env = dict(os.environ, PERL_CPANM_HOME=os.path.join(work, "cpanm"))
for target in [m for _, m in DISTS] + [p for p, _ in DISTS]:
    current[0] = target
    r = subprocess.run(["cpanm", "-n", "-L", os.path.join(work, "local", target.replace("/", "_")),
                        "--mirror", mirror, "--mirror-only", target], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        log.append((target, "CLIENT-ERROR", (r.stdout + r.stderr).strip().splitlines()[-1]))
server.shutdown()

version = subprocess.run(["cpanm", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
print("# Regenerate: docker run --rm -v \"$PWD/nora-registry/testdata/cpan:/w:ro\" perl:5.40 python3 /w/client_requests.py > nora-registry/testdata/cpan/client-requests.tsv")
print(f"# {version.rsplit(' (', 1)[0]}, perl:5.40, mirror http://127.0.0.1:<port>/cpan")
print("# installed\tmethod\tpath")
for row in log:
    print("\t".join(row))
