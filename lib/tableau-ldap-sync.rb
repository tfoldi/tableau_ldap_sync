require "yaml"

module TableauLDAPSync

  def load_configuration
    @config = YAML.load_file "config/config.yml" 
  end

  def config
    @config
  end
  
  extend self  
end

TableauLDAPSync.load_configuration

require "tableau-ldap-sync/tableau"
