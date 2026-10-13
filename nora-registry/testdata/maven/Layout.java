// Paths maven-resolver builds for artifacts, their checksums and metadata (the resolver Maven
// 3.9 runs), from generated coordinates. One row per path: kind (artifact, checksum, metadata),
// groupId, artifactId, baseVersion, version, classifier, extension (metadata: its type), path.
import java.util.*;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.artifact.*;
import org.eclipse.aether.internal.impl.Maven2RepositoryLayoutFactory;
import org.eclipse.aether.metadata.*;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.spi.connector.layout.RepositoryLayout;

public class Layout {
    public static void main(String[] args) throws Exception {
        DefaultRepositorySystemSession session = new DefaultRepositorySystemSession();
        RemoteRepository repo = new RemoteRepository.Builder("nora", "default", "http://127.0.0.1/maven2/").build();
        RepositoryLayout layout = new Maven2RepositoryLayoutFactory().newInstance(session, repo);
        String[][] ga = {
            {"org.apache.commons", "commons-lang3"}, {"io.netty", "netty-tcnative-boringssl-static"},
            {"com.Example.Mixed", "Upper-Art"}, {"a", "my.artifact"}, {"org.example.deep.nested.group", "lib"},
        };
        String[] versions = {"3.14.0", "1.0", "1.0.0", "1.0-SNAPSHOT", "1.0-20261012.120000-1", "2.0.0-RC1",
            "4.1.100.Final", "1.0-beta-1", "20030203.000550", "1.0.0-SNAPSHOT", "1.0.0-20261012.120000-17"};
        String[][] ce = {{"", "jar"}, {"", "pom"}, {"sources", "jar"}, {"javadoc", "jar"}, {"linux-x86_64", "jar"},
            {"tests", "jar"}, {"", "tar.gz"}, {"bin", "zip"}, {"", "jar.asc"}, {"", "module"}};
        System.out.println("# Regenerate: docker run --rm -v \"$PWD/nora-registry/testdata/maven:/w:ro\" maven:3.9-eclipse-temurin-21 java -cp '/usr/share/maven/lib/*' /w/Layout.java > nora-registry/testdata/maven/layout.tsv");
        System.out.println("# maven-resolver " + Maven2RepositoryLayoutFactory.class.getPackage().getImplementationVersion()
            + " (Maven2RepositoryLayoutFactory), " + System.getProperty("java.version"));
        System.out.println("# kind\tgroupId\tartifactId\tbaseVersion\tversion\tclassifier\textension\tpath");
        for (String[] g : ga) {
            for (String v : versions) {
                for (String[] c : ce) {
                    Artifact a = new DefaultArtifact(g[0], g[1], c[0], c[1], v);
                    String path = layout.getLocation(a, false).toString();
                    row("artifact", a, path);
                    if (c[1].equals("jar") && c[0].isEmpty()) {
                        for (RepositoryLayout.ChecksumLocation cl : layout.getChecksumLocations(a, false, layout.getLocation(a, false))) {
                            row("checksum", a, cl.getLocation().toString());
                        }
                    }
                }
            }
            for (String v : new String[] {"", "1.0-SNAPSHOT", "1.0.0-SNAPSHOT"}) {
                Metadata m = new DefaultMetadata(g[0], g[1], v, "maven-metadata.xml", Metadata.Nature.RELEASE_OR_SNAPSHOT);
                System.out.println(String.join("\t", "metadata", g[0], g[1], v, v, "", "maven-metadata.xml",
                    layout.getLocation(m, false).toString()));
            }
            Metadata grp = new DefaultMetadata(g[0], "maven-metadata.xml", Metadata.Nature.RELEASE);
            System.out.println(String.join("\t", "metadata", g[0], "", "", "", "", "maven-metadata.xml",
                layout.getLocation(grp, false).toString()));
        }
    }

    static void row(String kind, Artifact a, String path) {
        System.out.println(String.join("\t", kind, a.getGroupId(), a.getArtifactId(), a.getBaseVersion(),
            a.getVersion(), a.getClassifier(), a.getExtension(), path));
    }
}
