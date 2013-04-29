require "tableau-ldap-sync"
require 'httpclient'
require 'uri'
require 'rexml/document' 

module TableauLDAPSync

  class Tableau
    
    def initialize(server_url)
      proxy = ENV['HTTP_PROXY']
      @http_client = HTTPClient.new(proxy)
      @http_client.set_cookie_store("cookie.dat")
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
      
      @authenticity_token = REXML::Document.new( response.body ).root.elements['authenticity_token' ]
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
