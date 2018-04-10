lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'okta-auth-proxy/version'

Gem::Specification.new do |s|
  s.name        = 'okta-auth-proxy'
  s.version     = OktaAuthProxy::VERSION
  s.date        = '2016-04-09'
  s.summary     = 'Okta for apps without SAML support'
  s.description = 'Auth backend for use with nginx to protect applications with Okta SAML'
  s.authors     = ['Dale Hamel']
  s.email       = 'dale.hamel@srvthe.net'
  s.files       = Dir['lib/**/*']
  s.bindir      = 'bin'
  s.executables << 'okta-auth-proxy'
  s.homepage    = 'https://github.com/dalehamel/okta-auth-proxy'
  s.license = 'MIT'
  s.add_runtime_dependency 'sinatra', ['=2.0.1']
  s.add_runtime_dependency 'omniauth', ['=1.8.1']
  s.add_runtime_dependency 'omniauth-saml', ['=1.10.0']
  s.add_runtime_dependency 'em-synchrony', ['=1.0.6']
  s.add_runtime_dependency 'thin', ['=1.7.2']
  s.add_runtime_dependency 'thor', ['>= 0.20.0']
  s.add_runtime_dependency 'activesupport', ['=5.2.0']
  s.add_development_dependency 'pry', ['=0.10.4']
  s.add_development_dependency 'pry-byebug', ['=3.6.0']
  s.add_development_dependency 'rake', ['=12.3.1']
  s.add_development_dependency 'simplecov', ['=0.16.1']
  s.add_development_dependency 'rspec', ['=3.7.0']
end
