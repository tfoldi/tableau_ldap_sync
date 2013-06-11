# Copyright (c) 2013, Starschema Ltd
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies, 
# either expressed or implied, of the  Project.

require "tableau_ldap_sync"

module TableauLDAPSync

  class TableauSync
    include TableauLDAPSync
    
    # main processor function
    def synchronize
      connect_to_ldap
      connect_to_tableau
      
      @ldap_groups = @ldap.ssos_for_all_ldap_groups
      
      search_for_new_users_to_add_to_tableau
      synchronize_all_group
    end
    
    def connect_to_ldap
      @ldap = LDAPSrc.new( 
        TableauLDAPSync.config["ldap"]["host"], 
        TableauLDAPSync.config["ldap"]["port"],
        TableauLDAPSync.config["ldap"]["dn"], 
        TableauLDAPSync.config["ldap"]["password"] 
      )    
    end
    
    def connect_to_tableau
      logger.debug "Connecting to #{TableauLDAPSync.config["tableau"]["url"]}" 
      @tableau = Tableau.new( TableauLDAPSync.config["tableau"]["url"] )
      @tableau.login( 
        TableauLDAPSync.config["tableau"]["user"], 
        TableauLDAPSync.config["tableau"]["password"] 
      )    
    end
    
    def search_for_new_users_to_add_to_tableau
      tableau_users = @tableau.get_users
      logger.debug "Tableau users (all): #{tableau_users}"

      ldap_users = @ldap_groups.collect {|key,val| val }.flatten.uniq
      logger.debug "ldap_users (all): #{ldap_users}"

      (ldap_users - tableau_users).each do |user|
        @tableau.create_user user
      end
    end
    
    def synchronize_all_group
      TableauLDAPSync.config["group_mapping"].each { |group| synchronize_group( group["tableau"], group["ldap"] ) }
    end
    
    def synchronize_group(tableau_group, ldap_group)
      tableau_users = @tableau.get_users tableau_group
      logger.debug "Tableau users (#{tableau_group}): #{tableau_users}"
      
      ldap_users = @ldap_groups[ldap_group]
      logger.debug "ldap_users in group #{ldap_group}: #{ldap_users}"
      
      # add missing users to the tableau group
      logger.debug "Adding users to group #{tableau_group}: #{ldap_users - tableau_users}"
      @tableau.add_users_to_group tableau_group, ldap_users - tableau_users
      
      # remove users who are not in ldap
      logger.debug "Removing users from group #{tableau_group}: #{tableau_users - ldap_users}"
      @tableau.remove_users_from_group tableau_group, tableau_users - ldap_users 

    end
    
  end
end