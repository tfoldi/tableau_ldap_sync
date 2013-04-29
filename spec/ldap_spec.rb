require "tableau-ldap-sync"

module TableauLDAPSync
  
  describe :LDAP do
  
    it "should connect to ldap" do
	  ldapsrc = LDAPSrc.new( 
	    TableauLDAPSync.config["ldap"]["host"], 
        TableauLDAPSync.config["ldap"]["port"],
	    TableauLDAPSync.config["ldap"]["dn"], 
        TableauLDAPSync.config["ldap"]["password"] 
      )
    end

    it "should search a group" do
      ldapsrc = LDAPSrc.new( 
        TableauLDAPSync.config["ldap"]["host"], 
        TableauLDAPSync.config["ldap"]["port"],
        TableauLDAPSync.config["ldap"]["dn"], 
        TableauLDAPSync.config["ldap"]["password"] 
      )
	  
      p ldapsrc.ssos_for_group( 'cn=g00068100' )
    end

	
  end # describe
  
end # module