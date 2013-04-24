require "tableau-ldap-sync"

describe TableauLDAPSync::Tableau do

  it "should log on to the tableau server" do
    tableau = TableauLDAPSync::Tableau.new( TableauLDAPSync.config["tableau"]["url"] )
    tableau.login( 
      TableauLDAPSync.config["tableau"]["user"], 
      TableauLDAPSync.config["tableau"]["password"] 
    )
    
    users =  tableau.get( "/users.xml")
    doc = REXML::Document.new( users.body )
    doc.elements.each("users/user/name") { |element| puts element.text }

  end

end
