require "tableau-ldap-sync"

module TableauLDAPSync
  
  describe :Tableau do
    
    context "before successful logon" do 
      before do
        @tableau = Tableau.new( TableauLDAPSync.config["tableau"]["url"] )
      end
            
      it "should log on to the tableau server" do
        @tableau.login( 
          TableauLDAPSync.config["tableau"]["user"], 
          TableauLDAPSync.config["tableau"]["password"] 
        )
      end
    end

    context "before successful logon" do 
      before do
        @tableau = Tableau.new( TableauLDAPSync.config["tableau"]["url"] )
        @tableau.login( 
          TableauLDAPSync.config["tableau"]["user"], 
          TableauLDAPSync.config["tableau"]["password"] 
        )
      end

      it "should get the list of users in group Admins" do
        users =  @tableau.get( "/users.xml", {'fe_group' => 'local\Pricing Analytics' })
        doc = REXML::Document.new( users.body )
        #doc.elements.each("users/user/name") { |element| print element.text }
        #doc.elements.each("users/user/name") { |element| element.text.should == 'local\admin' }
      end
     

      it "should add two users" do
	    p @tableau.authenticity_token
        getpage = @tableau.post('/manual/create/users',  {
			'authenticity_token' => @tableau.authenticity_token,
			'step' => 1,
			'name' => 'GEINDSYS-AMER\\502011686',
			'level' => 'interactor'
		})
        p getpage.body        
		p @tableau.authenticity_token
        getpage = @tableau.post('/manual/create/users',  {
			'authenticity_token' => @tableau.authenticity_token,
			'step' => 1,
			'name' => 'GEINDSYS-AMER\\501863562',
			'level' => 'interactor'
		})
  
	  end      
    
      it "should create a user" do
        # 502011686
        ret = @tableau.post( "/manual/upload_action/system_users", { 
          'reason' => 'import',
          'filename' => 'group.csv',
       #   'uploaded_file' => "STARSCHEMA\\tfoldi,,,Interactor\n" ,
          'uploaded_file' => "GEINDSYS-AMER\\502011686,,,Interactor\n" ,
          'admin' => 'none',
          'format' => 'xml',
          'publisher' => 'false',
          'with_transaction' => 'false',
          'authenticity_token' => @tableau.authenticity_token
          } 
         )
        print ret.body
      end
    end

  end # descripte
end # module