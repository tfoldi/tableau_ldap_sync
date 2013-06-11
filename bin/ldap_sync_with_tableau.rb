require "tableau_ldap_sync" 

module TableauLDAPSync
  ts = TableauSync.new
  ts.synchronize
end

