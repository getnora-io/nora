# Regenerate: docker run --rm -v "$PWD/nora-registry/testdata/gems:/w:ro" ruby:3.4-slim ruby /w/full_names.rb > nora-registry/testdata/gems/full-names.tsv
# Prints gem file names as RubyGems itself builds them (Gem::Specification#file_name),
# one per line: name <TAB> version (Gem::Version#to_s) <TAB> platform (Gem::Platform#to_s,
# empty for ruby) <TAB> file name.
require "rubygems"
names = %w[rails rack-test devise-2fa ffi sorbet-static nokogiri foo-2-bar evil-1 a-1 x
           Flask_RESTful my.gem Mixed-Case foo-1.0-x86_64-linux ruby-2.0 jruby-openssl 123abc
           a1-2-3 net-http-2 x86_64-linux java 1-java]
versions = %w[0 1 1.0 1.13.0 7.1.0.rc1 1.0.0-rc1 1.0.0-rc-1 2.0.0.pre 0.5.11000 1.0.a 3.0.0-beta.2 19 2]
platforms = %w[java jruby x86_64-linux x86_64-linux-gnu x86_64-linux-musl aarch64-linux
               arm-linux-gnueabihf arm64-darwin x86_64-darwin-19 universal-darwin-20 universal-darwin
               x86-mingw32 x64-mingw32 x64-mingw-ucrt x86-mswin32 x86-mswin32-60 mswin32 i386-mswin32
               i686-linux universal-java-1.8 universal-java x86_64-freebsd-13 x86_64-openbsd-7.3
               sparc-solaris-2.11 powerpc-aix-7 x86-cygwin wasm32-wasi arm-dalvik-24 universal-dotnet
               universal-dotnet-4.0 x86_64-unknown bar 2.0-java 1-java x86_64-netbsdelf
               universal-macruby-0.10 darwin19 linux]
pairs = [%w[nokogiri 1.13.0], %w[sorbet-static 0.5.11000], %w[evil-1 2.0], %w[a-1 1],
         %w[foo-2-bar 1.0.0-rc1], %w[x86_64-linux 1], %w[java 19]]
def row(name, version, platform)
  spec = Gem::Specification.new do |s|
    s.name = name
    s.version = version
    s.platform = platform if platform
  end
  plat = spec.platform.to_s
  plat = "" if plat == Gem::Platform::RUBY
  puts [spec.name, spec.version.to_s, plat, spec.file_name].join("\t")
end
puts "# RubyGems #{Gem::VERSION} (Ruby #{RUBY_VERSION})"
names.each { |n| versions.each { |v| row(n, v, nil) if Gem::Version.correct?(v) } }
pairs.each { |n, v| platforms.each { |p| row(n, v, p) } }
