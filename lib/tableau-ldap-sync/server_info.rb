require 'net/http'
require 'logger'
require 'uri'
require 'rexml/document'

module TableauLDAPSync

  class ServerInfo

    def compose_url(relative_url)
      URI.join(@base_url, relative_url)
    end
    
    
    def write_token
      path = "session.token"
      success = File.open( path , 'w') do |token|
        [@base_url, @username, @session_id, @proxy_host, @proxy_port, nil,
         nil, @authenticity_token, @site_namespace, @site_prefix].each do |val|
          token.write("#{val}\n")
        end
        token.close
        logger.debug "Saved login cookie to #{path}"
        true
      end
      logger.warn "Unable to save login cookie to #{path}" unless success
    end

    def logger
      @logger
    end
  
    def initialize
      @logger = ::Logger.new(STDOUT)
      @base_url = TableauLDAPSync.config["tableau"]["url"]
      @username = TableauLDAPSync.config["tableau"]["user"]
      @password = TableauLDAPSync.config["tableau"]["password"]
    end 

    def reuse_session?
      !@session_id.nil? && !@authenticity_token.empty?
    end

    def login
      is_current = reuse_session?
      if is_current
        logger.info "Continuing previous session"
      else
        logger.info "Creating new session"
      end
      logger.info "    Server:   #{@base_url}"
      logger.info "    Username: #{@username}"
      return if is_current

      @session_id = nil

      write_token
      key = request_public_key('manual/auth?format=xml', 'authinfo')
      @session_id = send_password(key)
      write_token
    end

    def login!
      # Trash old session_id
      @session_id = nil
      @authenticity_token = ""
      login
    end

    def set_headers(request)
      request.set_cookie('workgroup_session_id', @session_id) if @session_id
      request['User-Agent'] = 'Tabcmd'
      request
    end

  
    def create_request(relative_url, type = 'Get')
      url = compose_url(relative_url)
      request = case type
      when 'Get'
        Net::HTTP::Get.new(url.request_uri)
      when 'Post'
        Net::HTTP::Post.new(url.request_uri)
      when 'Put'
        Net::HTTP::Put.new(url.request_uri)
      when 'Delete'
        Net::HTTP::Delete.new(url.request_uri)
      else
        raise "Invalid request type #{type}"
      end
      set_headers(request)
      request
    end

    def execute_request(relative_url, type = 'Get', opts = {})
      execute(create_request(relative_url, type), opts)
    end
    
    
    def request_public_key(key_url, tag, opts = {})
      logger.info "Connecting to server..."
      request = create_request(key_url, 'Get')
      opts[:signal_success] = false if opts[:signal_success].nil?
      opts[:auto_login] = false if opts[:auto_login].nil?
      response = execute(request, opts)

      @session_id = response.get_cookie('workgroup_session_id') if response.get_cookie('workgroup_session_id')

      key = OpenSSL::PKey::RSA.new
      begin 
        doc = REXML::Document.new( response.body )
        authinfo = doc.elements[1, tag]
        modulus = authinfo.elements[1, 'modulus']
        exponent = authinfo.elements[1, 'exponent']
        atoken = authinfo.elements[1, 'authenticity_token']
        @authenticity_token = atoken.text unless atoken.nil? # pubkey doesn't return an auth token (but that's ok, we already logged in)

        key.n = modulus.text.to_i(16)
        key.e = exponent.text.to_i(16)
      rescue  Exception => e 
        logger.debug "Exception is "  + e
        logger.debug "Public key response from server:"
        logger.debug response.body
        raise RuntimeError, "Unexpected response from server during authentication."
      end
      return key
    end
   
    def execute(request, opts = {})
      auto_login     = opts[:auto_login].nil?     ? true : opts[:auto_login]
      signal_success = opts[:signal_success].nil? ? true : opts[:signal_success]
      signal_failure = opts[:signal_failure].nil? ? true : opts[:signal_failure]
      filename = opts[:filename]
      relative = opts[:relative]
      base = URI.parse(@base_url)
      klass = Net::HTTP
      http = klass.new(base.host, base.port)
      if @timeout
        http.read_timeout = @timeout
      elsif opts[:read_timeout]
        http.read_timeout = opts[:read_timeout]
      end
      # Add a command line option to control this
      # http.set_debug_output $stderr

      # B45749 - in a case of a file download, the response body is saved into a file,
      # which means the response object does not have a usable body
      if filename || relative
        response = http.request(request){|resp|
          if resp.is_a? Net::HTTPSuccess
      # figure out where to save the response.body
            saved_filename = saved_get_filename(filename, relative, resp)
            File.open(saved_filename,'wb'){ |f|
              resp.read_body{ |seg|
              f.write seg
              }
            }
            logger.info "Saved #{relative} to #{saved_filename}."
          end
        }
      else
        response = http.request(request)
      end
      
      case response
      when Net::HTTPSuccess
        logger.info "Succeeded" if signal_success unless @silent
        return response
      when Net::HTTPRedirection
        location = URI.parse(response['Location'])
        if location.path == '/auth/'
          raise LoginRequired, "Authorization required" unless auto_login
          return retry_after_login(request, opts)
        elsif
          opts[:redirects] ||= 4
          raise(RuntimeError, "The server issued too many redirections") if opts[:redirects] <= 0
          opts[:redirects] -= 1

          # You'd think you could just re-set the destination on an existing request,
          # but I don't see how

          # we should never ever Post to /views or /workbooks (redirects from successful login to paid/public, so force a Get here
          if ['/views','/workbooks'].include?(location.path)
            redirect = Net::HTTP::Get.new(location.request_uri)
          else
            if location.path !~ /^\/manual/
              location.path = '/manual' + location.path
            end
            redirect = request.class.new(location.request_uri)
          end
          set_headers(redirect)
          redirect.body = request.body

          if !redirect.is_a?(Net::HTTP::Get)
            params = [ text_to_multipart('authenticity_token', @authenticity_token) ]
            redirect.set_multipart_form_data(params) # this wipes out other multipart params (maybe it should be update instead)
          end

          return execute(redirect, opts)
        end
      when Net::HTTPUnauthorized
        return retry_after_login(request, opts) if auto_login
      end
      logger.debug request.path
      display_error(response) if signal_failure
      return response
    end
 
    def display_error(response, do_raise = true)
      logger.error "Error:  " +  response
    end
    
    def raw_to_hex(raw)
#      hex = ""
#      0.upto(raw.length-1) do |i|
#        logger.debug raw[i]
#        logger.debug raw.unpack('H*')[i]
#        hex += raw.unpack('H*')[i]
#      end
#      hex
      raw.unpack("H*")
    end
    
    def assymmetric_encrypt(val, public_key)
      crypt_binary =  public_key.public_encrypt(val)
      raw_to_hex(crypt_binary)
    end

    def send_password(key)
      logger.info "Logging in..." + key.to_s
      request = create_request('manual/auth/login', 'Post')
      crypt_password = assymmetric_encrypt(@password, key)
      #password no longer needed
      @password = nil

      params = []
      params += [ ['username', @username]     ]
      params += [ ['format',   'xml']         ]
      params += [ ['crypted', crypt_password] ]
      params += [ ['authenticity_token', @authenticity_token] ]
      request.set_multipart_form_data(params)
      begin
        response = execute(request, { :signal_success => false, :auto_login => false })
      rescue StandardError => ex
        logger.debug "Login error #{ex.class} #{ex.message}"
        raise RuntimeError, "Incorrect username or password."
      end
      
      doc = REXML::Document.new( response.body )
      if doc.elements["error"].nil?
        prefix = doc.elements["successful_login/user/site_prefix"].text
        unless prefix.nil?
          @site_prefix = prefix.gsub(%r<^/>,'') + "/"
        else
          @site_prefix = ""
        end
      elsif doc.elements["error/sites"]
        message = "Site not found. Please use SITEIDs from the following sites:"
        doc.elements.each("error/sites/site") {
          |e| message += "\n\nNAME: #{e.text} \nSITEID: \"#{e.attributes["id"]}\""
        }
        raise RuntimeError, message
      else
        raise RuntimeError, doc.elements["error/message"].text
      end

      success = doc.elements[1, 'successful_login']
      # session id changes upon login, so get fresh token
      @authenticity_token = success.elements[1, 'authenticity_token'].text
      logger.debug "Authenticity token: #{@authenticity_token}"

      display_error( response ) unless success
      logger.info "Login Succeeded."
      return response.get_cookie('workgroup_session_id')
    end

    end # class   
end # module
