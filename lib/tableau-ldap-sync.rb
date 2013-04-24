require "yaml"

module TableauLDAPSync

  def self.load_configuration
    @config = YAML.load_file "config/config.yml" 
  end

  def self.config
    @config
  end
end

TableauLDAPSync.load_configuration

require "tableau-ldap-sync/http_header_addin"
require "tableau-ldap-sync/server_info"
require "tableau-ldap-sync/tableau"
