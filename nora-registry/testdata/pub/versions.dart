// How pub reads a version: pub_semver's Version.parse (what `dart pub` and pub.dev parse a
// pubspec and a listing with) and pub.dev's canonicalizeVersion (app/lib/shared/utils.dart:50,
// what the archive and version endpoints look a version up by). One row per string: the
// string, the canonical form pub.dev looks it up by (INVALID: pub_semver does not parse it).
// Two strings with one canonical form are one version to pub_semver (`==`) and to pub.dev.
import 'package:pub_semver/pub_semver.dart';

String? canonicalizeVersion(String version) {
  if (version.trim().isEmpty) return null;
  Version v;
  try {
    v = Version.parse(version);
  } on FormatException {
    return null;
  }
  final pre = v.preRelease.isNotEmpty ? v.preRelease.join('.') : null;
  final build = v.build.isNotEmpty ? v.build.join('.') : null;
  final canonical = Version(v.major, v.minor, v.patch, pre: pre, build: build);
  if (v != canonical) return null;
  return canonical.toString();
}

void main() {
  final cores = ['0.0.0', '1.0.0', '1.2.3', '01.2.3', '1.02.3', '1.2.03', '00.0.0', '10.20.30', '007.0.1'];
  final pres = ['', '-dev', '-dev.1', '-dev.01', '-Dev.1', '-alpha', '-Alpha', '-alpha.1.beta', '-0', '-00',
      '-rc-1', '-x.7.y', '-beta.11', '-1.0', '-a-b-c', '-99999999999999999999'];
  final builds = ['', '+1', '+01', '+build.7', '+Build.7', '+a-b', '+001.x', '+0', '+sha.5114f85'];
  final inputs = <String>{};
  for (final c in cores) {
    for (final p in pres) {
      for (final b in builds) {
        inputs.add('$c$p$b');
      }
    }
  }
  inputs.addAll(['1.0', '1', 'v1.0.0', 'V1.0.0', '1.0.0-', '1.0.0+', '1.0.0-a..b', '1.0.0+a..b',
      ' 1.0.0', '1.0.0 ', '1.0.0_1', '1.0.0-a_b', '1.0.0-ä', '1.0.0.0', '1.0.0-rc.1+', '-1.0.0',
      '99999999999999999999.0.0', '9223372036854775807.0.0', '9223372036854775808.0.0', '1.0.0+1+2',
      '1.0.0-+', '1.0.0--', '1.0.0-.', 'latest', '1.0.0/..', '1.0.0%2B1']);
  for (final v in inputs) {
    print('$v\t${canonicalizeVersion(v) ?? 'INVALID'}');
  }
}
