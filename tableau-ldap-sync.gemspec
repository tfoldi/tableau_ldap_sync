# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)

Gem::Specification.new do |s|
  s.name        = "tableau-ldap-sync"
  s.version     = "1.0"
  s.authors     = ["Tamas Foldi"]
  s.email       = ["tfoldi@starschema.net"]
  s.homepage    = "http://jruby-extras.rubyforge.org/jruby-ldap"
  s.summary     = "Synchronize LDAP groups with Tableau Server Groups"
  s.description = "Synchronize LDAP groups with Tableau Server Groups"
 
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_dependency( "jruby-ldap" )
end
