# Regenerate (three RubyGems, their union is the corpus; see readings.sh):
#   ruby readings.rb > readings-<version>.tsv     under each RubyGems
# Every way RubyGems can read a gem file name: for each `-` split into name, version and the
# rest, the split is a reading when the name is one Gem::SpecificationPolicy takes (its
# VALID_NAME_PATTERN, not starting with a special character; a letter is not required, as
# older gems have none), the version is one Gem::Version writes (`correct?` and `to_s` gives
# it back), and the rest is empty, a platform Gem::Platform writes (`to_s`), a platform a release
# on rubygems.org carries (platforms.tsv: older gems keep the spelling they were built with,
# `mswin32`, `i386-mingw32`, `jruby`), or a content address (Gem::ContentAddress, where this
# RubyGems has it).
# One row per file name: the stem, then its readings sorted as name|version|platform (empty for
# ruby), joined by `;` (empty: no reading).
require "rubygems"

NAME = Gem::SpecificationPolicy::VALID_NAME_PATTERN
SPECIAL = Gem::SpecificationPolicy::SPECIAL_CHARACTERS
CONTENT_ADDRESS = (Gem.const_defined?(:ContentAddress) ? /\A[0-9a-f]{8,64}\z/ : nil)
EXISTING = File.readlines(File.join(__dir__, "platforms.tsv")).reject { |l| l.start_with?("#") }
                .map { |l| l.split("\t").first }

def name?(name)
  NAME.match?(name) && !SPECIAL.match?(name)
end

def version?(version)
  Gem::Version.correct?(version) && Gem::Version.new(version).to_s == version
rescue ArgumentError
  false
end

# A platform RubyGems writes: Gem::Platform#to_s of some platform. `to_s` does not always read
# back as itself (RubyGems 3.6 writes the CPU-less `darwin19` as `darwin-19`, which it reads as CPU
# `darwin`), so the platforms tried are the suffix itself and the suffix with one `-` taken out
# or made `_` (`mswin32_60`).
def platform?(platform)
  return true if CONTENT_ADDRESS && CONTENT_ADDRESS.match?(platform)
  return true if EXISTING.include?(platform)
  candidates = [platform]
  platform.enum_for(:scan, "-").map { Regexp.last_match.begin(0) }.each do |at|
    candidates << platform[0...at] + platform[at + 1..]
    candidates << platform[0...at] + "_" + platform[at + 1..]
  end
  candidates.any? do |candidate|
    Gem::Platform.new(candidate).to_s == platform
  rescue StandardError
    false
  end
end

def readings(stem)
  fields = stem.split("-", -1)
  (1...fields.size).filter_map do |at|
    name = fields[0...at].join("-")
    version = fields[at]
    platform = at + 1 < fields.size ? fields[at + 1..].join("-") : nil
    next unless name?(name) && version?(version) && (platform.nil? || platform?(platform))
    [name, version, platform || ""].join("|")
  end.sort
end

names = %w[foo foo-bar evil-1 a-1 x a1-2-3 ffi-1.15.5-universal-darwin x86_64-linux java 1-java foo_bar
           Foo.Bar 123abc net-http-2 ruby-2.0 jruby-openssl devise-2fa sorbet-static -foo foo- .foo _foo]
versions = %w[0 1 1.0 1.0.0 1.0.a 1.0.0.pre.rc1 1.0_1 1..0 1. 01 19 2fa 1.0.0.RC1 0.5.11000 7.1.0.rc1]
platforms = [nil] + %w[java jruby x86_64-linux x86-mswin32-60 universal-darwin-19 universal-darwin-20 darwin19
                       darwin-19 darwin x86-my_platform x86-test_platform x86--linux x86-linux- -linux
                       x86_64-linux-gnu x86_64-linux-musl aarch64-linux arm-linux-gnueabihf x64-mingw-ucrt
                       x64-mingw32 universal-java-1.8 universal-java wasm32-wasi arm-dalvik-24
                       universal-dotnet-4.0 x86-cygwin sparc-solaris-2.11 powerpc-aix-7 x86_64-freebsd-13
                       x86_64-openbsd-7.3 x86_64-netbsdelf universal-macruby-0.10 x86_64-unknown unknown bar
                       2.0-java 1-java mswin32 i386-mswin32 x86-mswin32 deadbeef DEADBEEF 0123456789ab
                       0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef linux x86 x86_64]
stems = []
names.each { |n| versions.each { |v| platforms.each { |p| stems << [n, v, p].compact.join("-") } } }
%w[foo evil-1 a-1].each do |n|
  %w[1 1.0 0.5.11000].each { |v| EXISTING.each { |p| stems << [n, v, p].join("-") unless p == "ruby" } }
end
stems += %w[a-1-1-1-1-1-1-1-1-x-linux a-1-1-1-1-1-1-1-1-1-x-linux a-1-1-1-1-1-1-1-1-1-1-x-linux
            evil-1-2.0-java ffi-1.15.5-universal-darwin-19 acme-1-2.0-java noversion x-1.0-]
puts "# RubyGems #{Gem::VERSION} (Ruby #{RUBY_VERSION})#{CONTENT_ADDRESS ? ', content addresses' : ''}"
stems.uniq.sort.each { |stem| puts [stem, readings(stem).join(";")].join("\t") }
