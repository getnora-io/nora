# How CPAN reads a distribution path: CPAN::DistnameInfo, which the PAUSE indexer
# (PAUSE/mldistwatch.pm, PAUSE/dist.pm) and cpanm (Menlo::CLI::Compat::cpan_dist) both call.
# Inputs: the file names of the module's own test data (t/ext.t, t/path.t: real CPAN uploads),
# then generated paths (author directories, archive extensions in other case, version forms).
# One row per path: path, dist, version, extension, cpanid, maturity (UNDEF: none).
use strict;
use warnings;
use CPAN::DistnameInfo;

my ($work) = glob("$ENV{HOME}/.cpanm/work/*/CPAN-DistnameInfo-*");
my @paths;
for my $t ("ext.t", "path.t") {
    open my $fh, '<', "$work/t/$t" or die "$work/t/$t: $!";
    my $data = 0;
    while (<$fh>) {
        if (/^__DATA__/) { $data = 1; next }
        next unless $data;
        chomp;
        my ($file) = split /\s+/;
        push @paths, $file if defined $file && $file =~ /\S/ && $file !~ /^\s/;
    }
}
my @names = ("Foo-Bar-1.23", "Foo-Bar-1.23-TRIAL", "Foo-Bar-1.23_01", "Foo-Bar-v1.2.3", "Foo-Bar-v1.2.3_1",
             "CGI.pm-4.66", "Moose-2.2207", "libwww-perl-6.77", "Foo2-0.01", "Foo-Bar2-1.0",
             "Foo-Bar-1.23-withoutworldwriteables", "Foo_Bar-1.0", "Foo-Bar.1.0", "Foo-Bar-1.0.0.1", "foo-bar-1.0",
             "Foo-Bar-1.23-RC1", "Foo-Bar-0.01a", "Foo-Bar-undef", "Foo-Bar",
             # each fix-up of distname_info in both cases and at its boundaries
             "Foo-Bar-v3.1-0.1", "Foo-Bar-V3.1-0.1", "Foo-Bar-V3_1-2-0.1", "Foo-Bar-v3.1-2-0.1", "Foo-Bar-v1-2",
             "Foo-Bar-V1-x-2.0", "Foo-Bar-1a", "Foo-12b", "Foo-Bar12", "Foo-Bar-x_y-3-4.0", "A-B_C-1.0-2");
my @exts = (".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".tar.z", ".tar.Z", ".TAR.GZ", ".Zip", ".TGZ", ".tar.Gz", ".meta", ".readme");
for my $n (@names) {
    for my $e (@exts) {
        push @paths, "A/AU/AUTHOR/$n$e";
    }
}
push @paths, map { "authors/id/$_" } ("G/GB/GBARR/CPAN-DistnameInfo-0.12.tar.gz", "E/ET/ETHER/Moose-2.2207.tar.gz");
push @paths, ("X/XY/XYZ-9/Foo-1.0.tar.gz", "A/AB/ABC/sub/dir/Foo-1.0.tar.gz", "A/AU/AUTHOR/Perl6/Foo-1.0.tar.gz",
              "a/au/author/Foo-1.0.tar.gz", "A/AU/AUTHOR/CHECKSUMS", "A/AU/AUTHOR/Foo-1.0.tar.gz.sig");

my %seen;
print "# Regenerate: docker run --rm -v \"\$PWD/nora-registry/testdata/cpan:/w:ro\" perl:5.40 sh -c 'cpanm -q -n CPAN::DistnameInfo\@$CPAN::DistnameInfo::VERSION >/dev/null && perl /w/distnames.pl' > nora-registry/testdata/cpan/distnames.tsv\n";
print "# CPAN::DistnameInfo $CPAN::DistnameInfo::VERSION, perl $^V\n";
print "# path\tdist\tversion\textension\tcpanid\tmaturity\n";
for my $p (@paths) {
    next if $seen{$p}++;
    my $d = CPAN::DistnameInfo->new($p);
    print join("\t", $p, map { defined $_ ? $_ : "UNDEF" } $d->dist, $d->version, $d->extension, $d->cpanid, $d->maturity), "\n";
}
