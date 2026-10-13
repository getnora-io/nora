// What Maven sends to a repository at NORA's mount (`<server>/maven2`): an in-process HTTP
// server answers POMs, files, checksums and snapshot metadata built from the request path, and
// logs every request as the client wrote it; `mvn dependency:get` fetches each coordinate from it
// (the dependency plugin itself comes from Maven Central). One row per request: the coordinate
// fetched, method, path.
import com.sun.net.httpserver.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;

public class Client {
    static final List<String> log = Collections.synchronizedList(new ArrayList<>());
    static volatile String current = "";

    static byte[] body(String path) {
        Matcher snap = Pattern.compile("(.+)/([^/]+)/([^/]+-SNAPSHOT)/maven-metadata\\.xml").matcher(path);
        if (snap.matches()) {
            String g = snap.group(1).replace('/', '.'), a = snap.group(2), v = snap.group(3);
            String base = v.substring(0, v.length() - "-SNAPSHOT".length());
            String ts = base + "-20261012.120000-1";
            return ("<metadata><groupId>" + g + "</groupId><artifactId>" + a + "</artifactId><version>" + v
                + "</version><versioning><snapshot><timestamp>20261012.120000</timestamp><buildNumber>1</buildNumber></snapshot>"
                + "<lastUpdated>20261012120000</lastUpdated><snapshotVersions>"
                + "<snapshotVersion><extension>jar</extension><value>" + ts + "</value><updated>20261012120000</updated></snapshotVersion>"
                + "<snapshotVersion><extension>pom</extension><value>" + ts + "</value><updated>20261012120000</updated></snapshotVersion>"
                + "</snapshotVersions></versioning></metadata>").getBytes(StandardCharsets.UTF_8);
        }
        if (path.endsWith("/maven-metadata.xml")) return null;
        Matcher pom = Pattern.compile("(.+)/([^/]+)/([^/]+)/[^/]+\\.pom").matcher(path);
        if (pom.matches()) {
            return ("<project><modelVersion>4.0.0</modelVersion><groupId>" + pom.group(1).replace('/', '.')
                + "</groupId><artifactId>" + pom.group(2) + "</artifactId><version>" + pom.group(3)
                + "</version></project>").getBytes(StandardCharsets.UTF_8);
        }
        return ("file " + path).getBytes(StandardCharsets.UTF_8);
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            String raw = ex.getRequestURI().getRawPath();
            log.add(current + "\t" + ex.getRequestMethod() + "\t" + raw);
            String path = raw.replaceFirst("^/maven2/", "");
            byte[] out = null;
            try {
                for (String alg : new String[] {"sha1", "md5", "sha256", "sha512"}) {
                    if (path.endsWith("." + alg)) {
                        byte[] of = body(path.substring(0, path.length() - alg.length() - 1));
                        if (of != null) {
                            String name = alg.equals("sha1") ? "SHA-1" : alg.equals("md5") ? "MD5" : alg.equals("sha256") ? "SHA-256" : "SHA-512";
                            out = HexFormat.of().formatHex(MessageDigest.getInstance(name).digest(of)).getBytes();
                        }
                        break;
                    }
                }
                if (out == null && !path.matches(".*\\.(sha1|md5|sha256|sha512)$")) out = body(path);
            } catch (Exception e) {
                throw new IOException(e);
            }
            if (out == null) {
                ex.sendResponseHeaders(404, -1);
            } else {
                ex.sendResponseHeaders(200, ex.getRequestMethod().equals("HEAD") ? -1 : out.length);
                if (!ex.getRequestMethod().equals("HEAD")) ex.getResponseBody().write(out);
            }
            ex.close();
        });
        server.start();
        String repo = "nora::default::http://127.0.0.1:" + server.getAddress().getPort() + "/maven2";
        String[] coords = {"org.example:plain:1.0", "org.example:plain:1.0.0", "org.example:plain:1.0:jar:sources",
            "com.Example.Mixed:Upper-Art:2.0.0-RC1", "org.example:snap:1.0-SNAPSHOT", "org.example:tgz:1.0:tar.gz:bin",
            "org.example.deep.nested:my.artifact:4.1.100.Final", "org.example:plain:1.0:pom"};
        String version = "";
        for (String c : coords) {
            current = c;
            Process p = new ProcessBuilder("mvn", "-B", "-ntp", "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:get",
                "-Dartifact=" + c, "-DremoteRepositories=" + repo, "-Dtransitive=false")
                .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            if (p.waitFor() != 0) {
                String[] lines = out.strip().split("\n");
                log.add(c + "\tCLIENT-ERROR\t" + lines[lines.length - 1]);
            }
        }
        Process v = new ProcessBuilder("mvn", "-v").redirectErrorStream(true).start();
        version = new String(v.getInputStream().readAllBytes(), StandardCharsets.UTF_8).split("\n")[0];
        server.stop(0);
        System.out.println("# Regenerate: docker run --rm -v \"$PWD/nora-registry/testdata/maven:/w:ro\" maven:3.9-eclipse-temurin-21 java /w/Client.java > nora-registry/testdata/maven/client-requests.tsv");
        System.out.println("# " + version.replaceAll(" \\(.*", "") + ", maven-dependency-plugin 3.8.1 dependency:get, repository http://127.0.0.1:<port>/maven2");
        System.out.println("# coordinate\tmethod\tpath");
        for (String row : log) System.out.println(row);
    }
}
