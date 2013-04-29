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
     

      it "should return the get page" do
        #p "auth=" + @tableau.authenticity_token
        #getpage = @tableau.get('/new/users.xml')
        #p getpage.body
        #getpage = @tableau.get('/new/users.xml')
      #  p getpage.body
      end      
    
      it "should create a user" do
        # 502011686
        ret = @tableau.post( "/manual/upload_action/system_users", { 
          'reason' => 'import',
          'filename' => 'group.csv',
          'uploaded_file' => "STARSCHEMA\\tfoldi,,,Interactor\n" ,
          'admin' => 'none',
          'format' => 'xml',
          'publisher' => 'false',
          'with_transaction' => 'true',
          'authenticity_token' => @tableau.authenticity_token
          } 
         )
        print ret.body
      end
    end

  end # descripte
end # module