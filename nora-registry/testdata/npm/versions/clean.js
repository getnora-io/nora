// npm's semver.clean (the form npm publish gives a version) for each input line, or INVALID.
const semver = require('/usr/local/lib/node_modules/npm/node_modules/semver')
const lines = require('fs').readFileSync(process.argv[2], 'utf8').split('\n').filter(l => l.length)
console.log(`# npm ${require('/usr/local/lib/node_modules/npm/package.json').version}, semver ${require('/usr/local/lib/node_modules/npm/node_modules/semver/package.json').version}`)
for (const v of lines) console.log(`${v}\t${semver.clean(v) ?? 'INVALID'}`)
