require 'tableau-ldap-sync'
require 'ldap'


module TableauLDAPSync

  class LDAPSrc
    include TableauLDAPSync

    def initialize(server, port, dn, pass)
      @conn = LDAP::Conn.new(host=server, port=port)
      @conn.bind(dn, pass)
    end

    def ssos_for_group(group)
      ary = []
      
      @conn.search( 'ou=gessogroups,ou=groups,o=ge.com', LDAP::LDAP_SCOPE_ONELEVEL, group, ['uniqueMember']) do |entry| 
        entry.vals('uniqueMember').each do |member_dn|
          member_dn =~ /(gessouid=[\w-]+)/
          member_dn = $1
          
          @conn.search( 'ou=geworker,o=ge.com', LDAP::LDAP_SCOPE_ONELEVEL, member_dn, ['georaclehrid'] ) do |sso| 
            ary << sso.vals('georaclehrid').first
          end # search sso
        end # iterate uniqueMember
      end # search gessogroups

      ary
    end # def iterate
    
  end # class
  
end # module