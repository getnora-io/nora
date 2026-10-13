// What `dart pub get` sends to a hosted repository at NORA's mount (`PUB_HOSTED_URL=<server>/pub`):
// an in-process HTTP server answers the package listings and archives and logs every request
// as the client wrote it. Archive URLs in a listing are NORA's (`nora_archive_url`: the version
// percent-encoded with NORA's path-segment set, `+` kept). One row per request: package, version
// (empty for a listing), method, path as received.
import 'dart:convert';
import 'dart:io';

const packages = {
  'plain': '1.0.0',
  'build_meta': '1.0.0+1',
  'pre_release': '2.0.0-dev.1',
  'pre_and_build': '0.1.0-alpha.1+sha.5114f85',
  'dotted_build': '2.0.0+build.7',
  'mixed_pre': '1.2.3-x.7.y',
  'upper_pre': '3.0.0-Rc-1+Build.7',
  'hyphen_pre': '1.0.0--',
  '_underscore': '0.0.1',
  'Pong': '0.1.0',
  'RAL': '1.0.0+2',
};

String encodeSegment(String s) {
  const set = ' "#%/<>?[\\]^`{|}';
  final out = StringBuffer();
  for (final c in utf8.encode(s)) {
    if (c < 0x20 || c == 0x7f || c >= 0x80 || set.contains(String.fromCharCode(c))) {
      out.write('%${c.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    } else {
      out.writeCharCode(c);
    }
  }
  return out.toString();
}

Future<void> main() async {
  final work = Directory.systemTemp.createTempSync('pubm');
  final archives = <String, List<int>>{};
  for (final e in packages.entries) {
    final dir = Directory('${work.path}/src/${e.key}')..createSync(recursive: true);
    File('${dir.path}/pubspec.yaml')
        .writeAsStringSync('name: ${e.key}\nversion: ${e.value}\nenvironment:\n  sdk: ^3.0.0\n');
    Directory('${dir.path}/lib').createSync();
    File('${dir.path}/lib/${e.key}.dart').writeAsStringSync('');
    final tgz = '${work.path}/${e.key}.tar.gz';
    final r = Process.runSync('tar', ['-czf', tgz, '-C', dir.path, '.']);
    if (r.exitCode != 0) throw r.stderr;
    archives[e.key] = File(tgz).readAsBytesSync();
  }
  final log = <String>[];
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final base = 'http://127.0.0.1:${server.port}/pub';
  server.listen((req) async {
    final path = req.uri.path;
    String pkg = '', ver = '';
    final listing = RegExp(r'^/pub/api/packages/([^/]+)$').firstMatch(path);
    final archive = RegExp(r'^/pub/packages/([^/]+)/versions/(.+)\.tar\.gz$').firstMatch(path);
    if (listing != null && packages.containsKey(listing[1])) {
      pkg = listing[1]!;
      final v = packages[pkg]!;
      req.response.headers.contentType = ContentType('application', 'vnd.pub.v2+json');
      req.response.write(jsonEncode({
        'name': pkg,
        'latest': {'version': v, 'pubspec': {'name': pkg, 'version': v, 'environment': {'sdk': '^3.0.0'}},
                   'archive_url': '$base/packages/${encodeSegment(pkg)}/versions/${encodeSegment(v)}.tar.gz'},
        'versions': [
          {'version': v, 'pubspec': {'name': pkg, 'version': v, 'environment': {'sdk': '^3.0.0'}},
           'archive_url': '$base/packages/${encodeSegment(pkg)}/versions/${encodeSegment(v)}.tar.gz'}
        ],
      }));
    } else if (archive != null && packages.containsKey(Uri.decodeComponent(archive[1]!))) {
      pkg = Uri.decodeComponent(archive[1]!);
      ver = packages[pkg]!;
      req.response.headers.contentType = ContentType('application', 'octet-stream');
      req.response.add(archives[pkg]!);
    } else {
      req.response.statusCode = 404;
    }
    log.add('$pkg\t$ver\t${req.method}\t$path');
    await req.response.close();
  });

  final app = Directory('${work.path}/app')..createSync();
  final deps = packages.entries.map((e) => '  ${e.key}: "${e.value}"').join('\n');
  File('${app.path}/pubspec.yaml')
      .writeAsStringSync('name: app\nenvironment:\n  sdk: ^3.0.0\ndependencies:\n$deps\n');
  final r = await Process.run(Platform.resolvedExecutable, ['pub', 'get'],
      workingDirectory: app.path,
      environment: {'PUB_HOSTED_URL': base, 'PUB_CACHE': '${work.path}/cache'});
  await server.close(force: true);
  if (r.exitCode != 0) {
    stderr.writeln(r.stdout);
    stderr.writeln(r.stderr);
    exit(1);
  }
  print('# ${Platform.version.split(' (').first}: dart pub get, PUB_HOSTED_URL=http://127.0.0.1:<port>/pub');
  print('# package\tversion\tmethod\tpath');
  for (final line in (log..sort())) {
    print(line);
  }
}
