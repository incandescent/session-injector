require File.expand_path("../lib/session_injector/version", __FILE__)

Gem::Specification.new do |s|
  s.name        = "session_injector"
  s.version     = Rack::SessionInjector::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Aaron Hamid"]
  s.email       = ["aaron@incandescentsoftware.com"]
  s.homepage    = "http://github.com/incandescent/session-injector"
  s.summary     = "A Rack session injector middleware"
  s.description = "A Rack middleware that allows injecting a session across domains"

  s.required_rubygems_version = ">= 1.3.6"

  # lol - required for validation
  #s.rubyforge_project         = ""

  # If you have other dependencies, add them here
  s.add_dependency "activesupport", ">= 3"
  s.add_dependency "rack", ">= 1.2"

  s.files        = Dir["{lib}/**/*.rb", "bin/*", "LICENSE", "*.md"]
  s.require_path = 'lib'
end
