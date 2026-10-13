# Regenerate testdata/gems/platforms.tsv (from nora-registry/testdata/gems):
#   curl -sO https://rubygems.org/specs.4.8.gz && curl -sO https://rubygems.org/prerelease_specs.4.8.gz
#   docker run --rm -v "$PWD:/w:ro" ruby:3.4-slim ruby /w/platforms.rb > platforms.tsv
# Every distinct platform among the releases rubygems.org lists, as its indexes spell it, and how many
# releases carry it. A gem file on rubygems.org is named with one of these.
require "rubygems"
require "zlib"
counts = Hash.new(0)
%w[specs.4.8.gz prerelease_specs.4.8.gz].each do |f|
  Marshal.load(Zlib::GzipReader.open("/w/#{f}", &:read)).each do |_name, _version, platform|
    counts[platform.to_s] += 1
  end
end
puts "# rubygems.org specs.4.8 + prerelease_specs.4.8, #{Time.now.utc.strftime('%Y-%m-%d')}: platform, releases"
counts.sort_by { |p, n| [-n, p] }.each { |p, n| puts [p, n].join("\t") }
