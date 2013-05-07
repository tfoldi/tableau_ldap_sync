require "yaml"
require "logger"

module TableauLDAPSync
  

  def load_configuration
    @config = YAML.load_file "config/config.yml" 
  end

  def config
    @config
  end
  
  def logger
    @logger = Logger.new(STDOUT) if @logger.nil?
    @logger
  end
   
  extend self  
end

TableauLDAPSync.load_configuration

require "tableau-ldap-sync/tableau"
require "tableau-ldap-sync/ldapsrc"
