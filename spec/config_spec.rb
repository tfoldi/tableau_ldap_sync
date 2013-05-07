require "tableau-ldap-sync"

describe TableauLDAPSync do

  it "should load the config file" do
    TableauLDAPSync.config.should_not be_empty
    TableauLDAPSync.config["ldap"].should_not be_empty
    TableauLDAPSync.config["ad"].should_not be_empty
    TableauLDAPSync.config["tableau"].should_not be_empty
  end

  it "should iterate on group mappings" do
    TableauLDAPSync.config["group_mapping"].should_not be_empty
    TableauLDAPSync.config["group_mapping"].should be_an_instance_of(Array)
    TableauLDAPSync.config["group_mapping"].each do |map| 
      map.should be_an_instance_of(Hash)
      map.ldap.should be_an_instance_of(String) 
      map.tableau.should be_an_instance_of(String) 
    end    
  end
end
