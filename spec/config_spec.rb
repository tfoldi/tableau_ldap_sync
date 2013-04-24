require "tableau-ldap-sync"

describe TableauLDAPSync do

  it "should load the config file" do
    TableauLDAPSync.config.should_not be_empty
    TableauLDAPSync.config["ldap"].should_not be_empty
    TableauLDAPSync.config["ad"].should_not be_empty
    TableauLDAPSync.config["tableau"].should_not be_empty
  end

end
