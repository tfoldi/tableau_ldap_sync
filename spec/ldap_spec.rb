require "tableau_ldap_sync"

module TableauLDAPSync
  
  describe :LDAP do
  
    before do
      @ldapsrc = LDAPSrc.new( 
        TableauLDAPSync.config["ldap"]["host"], 
          TableauLDAPSync.config["ldap"]["port"],
          TableauLDAPSync.config["ldap"]["dn"], 
          TableauLDAPSync.config["ldap"]["password"] 
        )
    end


    it "should search a group" do
      p @ldapsrc.ssos_for_group( 'cn=g00418548' )
    end

    it "should show print all groups" do
      p @ldapsrc.ssos_for_all_ldap_groups
    end 
    
    it "should search a group and add its users" do
      @tableau = Tableau.new( TableauLDAPSync.config["tableau"]["url"] )
	  
      users = @ldapsrc.ssos_for_group( 'cn=g00418548' )

      @tableau.login( 
        TableauLDAPSync.config["tableau"]["user"], 
        TableauLDAPSync.config["tableau"]["password"] 
      )
      
      users.each {|user| @tableau.create_user(user) }

    end
	
  end # describe
  
end # module