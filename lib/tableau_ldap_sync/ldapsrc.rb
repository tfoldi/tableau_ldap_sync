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
require 'ldap'


module TableauLDAPSync

  class LDAPSrc
    include TableauLDAPSync

    def initialize(server, port, dn, pass)
      logger.debug "Connecting to #{dn} at #{server}:#{port}"
      
      @conn = LDAP::Conn.new(host=server, port=port)
      @conn.bind(dn, pass)
    end
    
    def ssos_for_all_ldap_groups
      groups = {}
      TableauLDAPSync.config["group_mapping"].each { |group| groups[group['ldap']] = ssos_for_group(group['ldap']) } 
      groups
    end

    def ssos_for_group(group)
      ary = []
      logger.debug "Collecting users from group #{group}"
            
      @conn.search( 'ou=gessogroups,ou=groups,o=ge.com', LDAP::LDAP_SCOPE_ONELEVEL, group, ['uniqueMember']) do |entry| 
		if entry.vals('uniqueMember').nil?
		  logger.warn "group #{group} has no users in ldap -- removing ALL users from tableau" 
		  return ary
		end
        entry.vals('uniqueMember').each do |member_dn|
          member_dn =~ /(gessouid=[\w-]+)/
          member_dn = $1
          
          @conn.search( 'ou=geworker,o=ge.com', LDAP::LDAP_SCOPE_ONELEVEL, member_dn, ['georaclehrid'] ) do |sso| 
            ary << sso.vals('georaclehrid').first
          end # search sso
        end # iterate uniqueMember
      end # search gessogroups

      logger.debug "SSO list for group #{group} is #{ary.join(', ')}"      
      ary
    end # def iterate
    
  end # class
  
end # module