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
require 'httpclient'
require 'uri'
require 'rexml/document' 

module TableauLDAPSync

  class Tableau
    include TableauLDAPSync
    
    def initialize(server_url)
      proxy = ENV['HTTP_PROXY']
      @http_client = HTTPClient.new(proxy)
      @http_client.debug_dev = STDOUT if $DEBUG
      
      @server_url = server_url
    end
    
    def authenticity_token
      @authenticity_token.text
    end
    
    def login(user, pass)
      key = OpenSSL::PKey::RSA.new
      
      # invoke /auth.xml on server
      response = get( '/manual/auth.xml' )
      
      # parse returned XML
      doc = REXML::Document.new( response.body )
      
      # read RSA key + authenticity token
      authinfo = doc.elements[1, 'authinfo']
      modulus = authinfo.elements[1, 'modulus']
      exponent = authinfo.elements[1, 'exponent']
      @authenticity_token = authinfo.elements[1, 'authenticity_token']
      
      # fill RSA key information
      key.n = modulus.text.to_i(16)
      key.e = exponent.text.to_i(16)

      # logon to server with encrypted password
      response = post('/manual/auth/login.xml', { 
          'authenticity_token' => authenticity_token, 
          'crypted' => assymmetric_encrypt(pass,key),
          'username' => user
        } 
      )

	  if response.body.include? "authfailure" then
		logger.error "Cannot logon to tableau due to authentication error"
		abort("Cannot communicate with Tableau - aborting")
	  end
	  
      @authenticity_token = REXML::Document.new( response.body ).root.elements['authenticity_token' ]
    end
    
    def create_user(user,domain = TableauLDAPSync.config["ad"]["domain"])
      logger.info "Create user #{user}@#{domain}"
      getpage = post('/manual/create/users',  {
        'authenticity_token' => authenticity_token,
        'step' => 1,
        'name' => "#{domain}\\#{user}",
        'level' => 'interactor'
      })
    end
    
    def get_users(group = 'All Users')
        users = get( "/users.xml", {'fe_group' => "local\\#{group}" })
        doc = REXML::Document.new( users.body ) 
        doc.elements.collect("users/user/name") { |element| element.text[/(\d+)$/] }    
    end
    
    def add_users_to_group(group, users)
      post( "/manual/upload_add_or_remove_users/groups", { 
        'filename' => 'group.csv',
        'uploaded_file' => users.join("\n") ,
        'group' => group,
        'format' => 'xml',
        'with_transaction' => 'true',
        'authenticity_token' => authenticity_token
        } 
      )      
    end

    def remove_users_from_group(group, users)
      post( "/manual/upload_add_or_remove_users/groups", { 
        'filename' => 'group.csv',
        'uploaded_file' => users.join("\n") ,
        'group' => group,
        'format' => 'xml',
        'do_remove' => 'true', 
        'with_transaction' => 'true',
        'authenticity_token' => authenticity_token
        } 
      )      
    end
    
    def tableau_url_with(path)
      URI.join(@server_url, path)
    end
  
    # Encrypt test with RSA public key and pack as %.0x hex numbers
    def assymmetric_encrypt(val, public_key)
      crypt_binary =  public_key.public_encrypt(val)
      crypt_binary.unpack("H*")
    end
  
    def get(path, params = {} )
      @http_client.get( tableau_url_with(path), params) 
    end
    
    def post(path, params = {} )
      @http_client.post( tableau_url_with(path), params) 
    end
    
  end
end
