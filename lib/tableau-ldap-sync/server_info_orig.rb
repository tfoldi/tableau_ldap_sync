# -*- coding: raw-text -*-
# -----------------------------------------------------------------------
# The information in this file is the property of Tableau Software and
# is confidential.
#
# Copyright (c) 2011 Tableau Software, Incorporated
#                    and its licensors. All rights reserved.
# Protected by U.S. Patent 7,089,266; Patents Pending.
#
# Portions of the code
# Copyright (c) 2002 The Board of Trustees of the Leland Stanford
#                    Junior University. All rights reserved.
# -----------------------------------------------------------------------

require 'net/https'
require 'http_util'
require 'hpricot'
require 'highline/import'
require 'json'
require 'environment_settings'

POLLING_INTERVAL = 1
RETRY_THRESHOLD = 0

class ServerInfo
  attr_accessor :certcheck, :no_prompt, :save_cookie, :timeout, :authenticity_token, :monitor, :silent
  attr_reader :password
  attr_reader :username

  include Http_Util
  # B58288 - storing the layout metrics for the bootstrap session
  #          (these values are defined in: viewer_bootstrap.js)
  METRICS_DB = '{"scrollbar": {"w": 17,"h": 17},"qfixed": {"w": 0,"h": 0},
                 "qslider": {"w": 0,"h": 20},"qreadout": {"w": 0,"h": 26},
                 "cfixed": {"w": 0,"h": 1},"citem": {"w": 0,"h": 17},
                 "cmdropdown": {"w": 0,"h": 24},"cmslider": {"w": 0,"h": 38},
                 "cmpattern": {"w": 0,"h": 22},"hfixed": {"w": 0,"h": 21},
                 "hitem": {"w": 0,"h": 20}}'

  def initialize
    @save_cookie = true
    @version = {}
    @authenticity_token = ""
    @monitor = true
    @silent = false
    @site_namespace = ""
    @site_prefix = ""
    @locale = nil
    @certcheck = true
    read_token
  end

  def base_url
    @base_url
  end

  def base_url=(value)
    if value =~ /([^\/:]*):\/\/(.*)/
      protocol, path = Regexp.last_match[1,2]
      unless protocol == "http" || protocol == "https"
        raise "Protocol '#{protocol}' is not supported"
      end
      url = "#{protocol}://#{path}"
    else
      logger.debug("Server name #{value} did not contain ://.")
      raise "Please specify 'http://' or 'https:// before the server name."
    end
    unless url =~ /\/$/
      url += "/"
    end
    return if @base_url == url
    @base_url = url
    # Changing the url invalidates the session id
    @session_id = nil
    @sheet_id = nil
    @vizql_root = nil
    @vizql_session_id = nil
    @layout_id = nil
    @authenticity_token = ""
  end

  def site_prefix
    @site_prefix
  end

  def site_namespace
    @site_namespace
  end

  def site_namespace=(value)
    return if @site_namespace == value
    if value.nil?
      @site_namespace = ""
    else
      @site_namespace = value
    end
    @session_id = nil
    @authenticity_token = ""
    make_site_prefix()
  end

  def make_site_prefix
    if @site_namespace.nil? || @site_namespace.empty?
      @site_prefix = ""
    else
      @site_prefix = %Q[t/#{@site_namespace}/]
    end
  end

  def get_site_prefix
    if @site_prefix.nil?
      return ""
    else
      return @site_prefix
    end
  end

  def compose_url(relative_url)
    path = @base_url + get_site_prefix
      URI.join(path, relative_url)
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

  def create_command_request(ns, command, params = {})
    command_url = "#{@vizql_root}/sessions/#{@vizql_session_id}/commands/#{ns}/#{command}"
    request = create_request(url = command_url, type = 'Post')
    flat_params = []
    params.each_pair {|k,v| flat_params += [ text_to_multipart(k.to_s, v.to_json) ]}
    request.set_multipart_form_data(flat_params)
    request
  end

  def format_layout_method(method)
    "#{@vizql_root}/#{method}/sessions/#{@vizql_session_id}/layouts/#{@layout_id}"
  end

  def format_method_url(method)
    "#{@vizql_root}/#{method}/sessions/#{@vizql_session_id}"
  end

  def request_bootstrap(workbookView, screen_width = nil, screen_height = nil)
    # B47702 - omit the preceeding '/' from the request URL
    view_url = "views/" + workbookView
    view_response = Server.execute_request(url = view_url)
    # B48444 - detecting if view URL contains query string, then constructing the embedded URL accordingly.
    s = view_url.include?('?') ? '&' : '?'
    embed_url = view_url + s + ":embed=y&:from_wg=true"
    view_response_embed = Server.execute_request(url = embed_url)

    def json_str_for_key(key, body)
      matches = /"?#{key}"?: ?"(.*)"/.match(body)
      if matches && matches.length > 0
        value = matches[1]
        # JSON.parse() needs handholding
        return JSON.parse("[\"" + (value.gsub(/\\x([0-9A-F]{2})/) { $1.to_i(16).chr}) + "\"]")[0]
      else
        return nil
      end
    end

    if view_response_embed
      body = view_response_embed.body
      @vizql_session_id = json_str_for_key("sessionid", body)
      @sheet_id = json_str_for_key("sheetId", body)
      @locale = json_str_for_key("locale", body)
      @vizql_root = json_str_for_key("vizql_root", body)
      # B48444 - retrieve the embed parameters from the response body
      showParamsValue = /"?#{"showParams"}"?: ?"(.*)"/.match(body)
      @embed_params = showParamsValue[1].gsub(/\\x/,'%') if showParamsValue && showParamsValue.length > 0
    end

    raise RuntimeError, "Failed to create session on server" if @vizql_session_id.nil?
    # B51305 - constructing bootStrap POST request with 'manual' prefix, so SSPI will be honored by Apache.
    @vizql_root ? @vizql_root = "/manual#{@vizql_root}" : "/manual/vizql"
    bootstrap_url = format_method_url("bootstrapSession")
    request = create_request(url = bootstrap_url, type = 'Post')

    form_params = {}
    form_params['sheet_id'] = URI.unescape(@sheet_id) if @sheet_id
    form_params['showParams'] = URI.unescape(@embed_params) if @embed_params
    # B58828,B57421
    form_params['metrics'] = METRICS_DB
    form_params['h'] = screen_height if screen_height
    form_params['w'] = screen_width if screen_width

    request.set_form_data(form_params)
    bootstrap_response = execute(request)

    if bootstrap_response
      body = bootstrap_response.body
      matches = /"layoutId":([0-9]+)/.match(body)
      @layout_id = nil
      @layout_id = matches[1] if (matches)
      raise RuntimeError, "Failed to find layout in response" if @layout_id.nil?
    end
  end

  def set_headers(request)
    request.set_cookie('workgroup_session_id', @session_id) if @session_id
    request['Accept-Language'] = @locale if @locale
    request['User-Agent'] = 'Tabcmd'
    request['X-Tsi-Active-Tab'] = @sheet_id if @sheet_id
    request
  end

  def display_error(response, do_raise = true)
    xml = Hpricot(response.body)
    errs = (xml/"error")
    unless errs && errs.size > 0
      logger.debug(response.body)
      response.error! if do_raise
    end
    text = []
    errs.each do |err|
      message = err/"/message"
      if message && message.size > 0
        text << message.inner_text
        details = (err/"/details").inner_text
        text << details if ( details && details.length > 0 )
      else
        text << err.inner_text
      end
    end
    text << "Operation Canceled." if do_raise
    msg = text.join("\n")
    # B23803.  &nbsp; comes out as two characters, number 194 and 160,
    msg.gsub!( 194.chr + 160.chr, ' ' )
    raise msg if do_raise
    msg
  end

  def assymmetric_encrypt(val, public_key)
    crypt_binary =  public_key.public_encrypt(val)
    raw_to_hex(crypt_binary)
  end

  def symmetric_encrypt(val, public_key)
    des = OpenSSL::Cipher::Cipher.new("des-ede3-cbc")
    des.encrypt

    # Create a random password that we'll use for DES encryption
    password = des.random_key
    des.encrypt
    des.key = password
    des.iv  = ['00000000000000000000000000000000'].pack('H*')
    # Encrypt the value
    e = des.update(val)
    e << des.final
    crypt_val = e.to_s

    # Note that we turn the password to hex both before and after
    # encrypting it.  I assume it's to ease debugging, but I'm not sure;
    # it's what desktop does, in any event.
    crypt_key = public_key.public_encrypt(raw_to_hex(password))

    return raw_to_hex(crypt_key), raw_to_hex(crypt_val)
  end

  def raw_to_hex(raw)
    hex = ""
    0.upto(raw.length-1) do |i|
      hex += sprintf("%0.2x", raw[i])
    end
    hex
  end

  class LoginRequired < RuntimeError
  end

  class SSLRequired < RuntimeError
  end

  # We only have the beginnings of https authentication here
  # On connect to https, you will see a warning
  # warning: peer certificate won't be verified in this SSL session
  # We need to ship a set of root certificates that we will accept and verify
  # against them, see this blog entry.
  # http://redcorundum.blogspot.com/2008/03/ssl-certificates-and-nethttps.html
  def execute(request, opts = {})
    auto_login     = opts[:auto_login].nil?     ? true : opts[:auto_login]
    signal_success = opts[:signal_success].nil? ? true : opts[:signal_success]
    signal_failure = opts[:signal_failure].nil? ? true : opts[:signal_failure]
    filename = opts[:filename]
    relative = opts[:relative]
    base = URI.parse(@base_url)
    if @proxy_host
      klass = Net::HTTP::Proxy(@proxy_host, @proxy_port)
    else
      klass = Net::HTTP
    end
    http = klass.new(base.host, base.port)
    http.use_ssl = (base.scheme == 'https')
    if http.use_ssl
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      # B59801 - validate the certificate using bundle of CA Root Certificates:
      # http://curl.haxx.se/ca/cacert.pem
      if @certcheck
        http.ca_file = File.join(File.dirname(__FILE__), "cacert.pem")
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.verify_depth = 5
      end
    end
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
      elsif location.scheme == 'https'
        raise SSLRequired, "The server only accepts HTTPS connections. Please check the server URL."
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
  
  # figure out where to save the file containing the response.body.
  def saved_get_filename(filename, relative, response)
  
  # If the user supplied a filename, just use it.
    if filename 
      return RelativePath.fix_path(filename)
    end

    # if the response is an attachment, then clean up the attachment name and use that as the filename
    if response.key?('content-disposition') 
      disposition = response['content-disposition']

      if disposition =~ /^attachment; filename="(.+)"$/
        disp_filename = $1
        # the server now returns the title of the wb as the filename, instead of
        # the repo_id. Must remove all the illegal Windows filename characters
        newfilename = disp_filename.gsub(/[":<>*?|\/\\]/, '_')
        if newfilename == disp_filename
          logger.info "Found attachment: #{disp_filename}."
        else
         logger.info "Found attachment: #{disp_filename} (remapped to #{newfilename})."
        end
        return RelativePath.fix_path(newfilename)
      end
    end
      
    # failing any of the above, just use relative as the filename.
    return RelativePath.fix_path(File.basename(URI.parse(relative).path))
  end
  
  # Invokes a server-side command with presentation model parameters.
  # Returns the result for the invoked command, automatically
  # parsing the JSON.
  # `opts' handles Server.execute options.
  def execute_command(ns, command, params = {}, opts = {})
    request = create_command_request(ns, command, params)
    response = execute(request, opts)

    command_return = nil
    if response && response.body
      body = response.body
      result = JSON.parse(body)

      command_results = result['vqlCmdResponse']['cmdResultList']
      command_results.each do |result|
        if result['commandName'] == "#{ns}:#{command}"
          command_return = result['commandReturn']
        end
      end
      unless command_return
        raise RuntimeError, "Bad command JSON response"
      end
    else
      raise RuntimeError, "Bad command response"
    end
    command_return
  end

  def request_tempfile(tempfileKey, opts = {})
    tempfile_url = "#{@vizql_root}/tempfile/sessions/#{@vizql_session_id}\/?key=#{tempfileKey}"
    tempfile_request = Server.create_request(url = tempfile_url)
    execute(tempfile_request, opts)
  end

  def get_token_path
    path = nil
    begin
      unless Tabcmd::Test
        dir = EnvironmentSettingsManager.app_data_tableau_directory
        FileUtils.makedirs dir
        path = File.join(dir, 'tabcmd.txt')
      else
        if ENV['TEMP']
          path = File.join(ENV['TEMP'], "tabcmd.#{$$}.txt")
        else
          logger.debug "Could not create token path because TEMP environment variable is not set."
        end
      end
    rescue StandardError => ex
      logger.debug "Failed to create token directory."
      logger.debug ex.message
    end
    path
  end

  def get_startup_auth_token()
    logger.info "    Startup"
    @session_id = nil
    @version = {}
    write_token
    key = get_authenticity_token('manual/startup')
    write_token
  end

  def reuse_session?
    !@session_id.nil? && is_current_version? && !@authenticity_token.empty?
  end

  def login
    is_current = reuse_session?
    if is_current
      logger.info "Continuing previous session"
    else
      missing = missing_args
      if missing
        raise RuntimeError, "Cannot login because of missing arguments: #{missing.join(',')}"
      end
      logger.info "Creating new session"
    end
    logger.info "    Server:   #{@base_url}"
    logger.info "    Proxy:    #{@proxy_host}:#{@proxy_port}" if @proxy_host
    logger.info "    Username: #{@username}"
    unless @site_namespace.eql?("") || @site_namespace.nil?
      logger.info "    Site:     #{@site_namespace}"
      make_site_prefix
    end
    return if is_current
    if (!@password && !@no_prompt)
      @password = ask("Password: ") {|q| q.echo = false}
    end
    @session_id = nil
    @version = {}
    # If they attempt to login and fail, we do not want to revert to any
    # earlier session info.  Write a token with the current (nil) session_id
    write_token
    key = request_public_key('manual/auth?format=xml', 'authinfo')
    require_current_version!
    @session_id = send_password(key)
    write_token
  end

  def login!
    # Trash old session_id
    @session_id = nil
    @authenticity_token = ""
    login
  end

  def logout
    begin
      execute(create_request('manual/auth/logout', 'Get'), :auto_login => false)
    rescue LoginRequired # Of course it is after we logout, don't bother reporting it
      logger.info "Log out completed."
    end
    @session_id = nil
    @authenticity_token = ""
    @site_namespace = ""
    @site_prefix = ""
    write_token
  end

  def delete_token
    path = get_token_path
    if path && File.exists?(path)
      begin
        File.delete(path)
      rescue StandardError => ex
        logger.warn "Unable to delete old login cookie #{path}"
        logger.debug "#{ex.class}: #{ex.message}"
        return nil
      end
    end
    return true
  end

  def missing_args
    missing = Array.new
    missing.push("--username") unless @username
    unless @password
      if @no_prompt
        missing.push("--password")
      end
    end

    missing.push("--server") unless @base_url

    if missing.length > 0
      return missing
    else
      return nil
    end
  end

  def password=(value)
    @password = value
  end

  def proxy_host=(value)
    return if @proxy_host == value
    @proxy_host = value
    @session_id = nil
    @authenticity_token = ""
  end

  def proxy_port=(value)
    return if @proxy_port == value
    @proxy_port = value
    @session_id = nil
    @authenticity_token = ""
  end

  def read_token
    path = get_token_path
    return unless path
    unless File.readable?(path)
      if File.exists?(path)
        logger.warn "Cannot read login cookie at #{path}"
      else
        logger.debug "No login cookie found at #{path}"
      end
      return nil
    end
    File.open(path , 'r') do |token|
      lines = token.readlines.map do |str|
        val = str.strip
        val if val != ""
      end
      if lines.size != 10
        logger.debug "Saved cookie file is outdated."
        return
      end
      @base_url, @username, @session_id, @proxy_host, @proxy_port, @version[:api_version], @version[:product_version], @authenticity_token, @site_namespace, @site_prefix = lines

      # some values need to be empty strings and not nil
      @authenticity_token = '' if @authenticity_token.nil?
      @site_namespace     = '' if @site_namespace.nil?
      @site_prefix        = '' if @site_prefix.nil?
    end
  end

  def get_authenticity_token(key_url, opts = {})
    logger.info "Getting Authenticity Token from server..."
    request = create_request(key_url, 'Get')
    response = execute(request, opts)

    @session_id = response.get_cookie('workgroup_session_id') if response.get_cookie('workgroup_session_id')
    @authenticity_token = ""

    begin
      doc = Hpricot(response.body)
      matches = (doc/"form")/'input[@name="authenticity_token"]'
      @authenticity_token = matches[0][:value].to_s
      logger.debug "Authenticity token: #{@authenticity_token}"
    rescue
      logger.debug "Unexpected Authenticity Token response from server:"
      logger.debug response.body
      raise RuntimeError, "Unexpected response from server fetching Authenticity Token."
    end
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
      logger.debug "Authenticity token: #{@authenticity_token}"

      key.n = modulus.text.to_i(16)
      key.e = exponent.text.to_i(16)

      version = authinfo.elements[1, 'version']

      if version
        version.elements.each do |e|
          @version[e.name.to_sym] = e.text
        end
        @version[:api_version] ||= version.attributes['version']
      end
    rescue
      logger.debug "Public key response from server:"
      logger.debug response.body
      raise RuntimeError, "Unexpected response from server during authentication."
    end
    return key
  end

  def is_current_version?
    XML_API_VERSION == @version[:api_version]
  end

  def require_current_version!
    unless is_current_version?
      if @version[:product_version]
        msg = "#{MultiCommand.appname} version #{ProductVersion.current} does not match Tableau Server version #{@version[:product_version]}."
      else
        msg = "#{MultiCommand.appname} version #{ProductVersion.current} is newer than your Tableau Server version."
      end
      msg += " You must use compatible versions of #{MultiCommand.appname} and Tableau Server."
      logger.debug "Tabcmd api version: '#{XML_API_VERSION}', product version '#{ProductVersion.current}', build '#{ProductVersion.rstr}'."
      logger.debug "Server api version: '#{@version[:api_version]}', product version '#{@version[:product_version]}', build #{@version[:build]}'."
      raise RuntimeError, msg
    end
    true
  end

  def retry_after_login(request, opts)
    missing = missing_args
    if missing
      raise "Your session has expired."
    else
      logger.info "Your session has expired.  Logging in again..."
    end
    login!
    request.set_cookie('workgroup_session_id', @session_id)
    if !request.is_a?(Net::HTTP::Get)
      params = [ text_to_multipart('authenticity_token', @authenticity_token) ]
      request.update_multipart_form_data(params)
    end
    opts[:no_auto_login] = true
    execute(request, opts)
  end

  def send_startup(key)
    logger.info "Setting Initial User..."
    request = create_request('manual/startup/1', 'Post')
    params = []
    params += [ text_to_multipart('format',   'xml')         ]
    params += [ text_to_multipart('authenticity_token', @authenticity_token) ]
    params += [ text_to_multipart('startup1[name]', @username) ]
    params += [ text_to_multipart('startup1[password]', @password)]
    params += [ text_to_multipart('startup1[friendly_name]', @friendly_name)]
    request.set_multipart_form_data(params)
    begin
      response = execute(request, { :signal_success => false, :auto_login => false })
    rescue StandardError => ex
      logger.debug "Login error #{ex.class} #{ex.message}"
      raise RuntimeError, "Incorrect username or password."
    end
    doc = REXML::Document.new( response.body )
    success = doc.elements[1, 'successful_startup']

    # session id changes upon login, so get fresh token
    @authenticity_token = success.elements[1, 'authenticity_token'].text
    logger.debug "Authenticity token: #{@authenticity_token}"

    display_error( response ) unless success
    logger.info "Startup Succeeded."
    return response.get_cookie('workgroup_session_id')
  end

  def send_password(key)
    logger.info "Logging in..."
    request = create_request('manual/auth/login', 'Post')
    crypt_password = assymmetric_encrypt(@password, key)
    #password no longer needed
    @password = nil

    params = []
    params += [ text_to_multipart('username', @username)     ]
    params += [ text_to_multipart('format',   'xml')         ]
    params += [ text_to_multipart('crypted', crypt_password) ]
    params += [ text_to_multipart('target_site', Server.site_namespace) ]
    params += [ text_to_multipart('authenticity_token', @authenticity_token) ]
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

  def session_id
    @session_id
  end

  def username
    @username
  end

  def username=(value)
    return if @username == value
    @username = value
    # Changing the username invalidates the session id
    @session_id = nil
    @authenticity_token = ""
  end

  def write_token
    unless @save_cookie
      delete_token
      return
    end
    path = get_token_path
    success = File.open( path , 'w') do |token|
      [@base_url, @username, @session_id, @proxy_host, @proxy_port, @version[:api_version],
       @version[:product_version], @authenticity_token, @site_namespace, @site_prefix].each do |val|
        token.write("#{val}\n")
      end
      token.close
      logger.debug "Saved login cookie to #{path}"
      true
    end
    logger.warn "Unable to save login cookie to #{path}" unless success
  end

  def with_silence
    old_silence = @silent
    begin
      @silent = true
      yield
    ensure
      @silent = old_silence
    end
  end

  ## some commands may return immediately with a job_id in the xml response.  If present, poll the job until completion
  def monitor_job(response)
    xml = Hpricot(response.body)
    job_id = (xml/"job_id")
    logger.debug("No job_id found in #{response.body}") if job_id.nil?
    completed = false
    status = nil
    failures = 0
    while job_id && !completed
      request = Server.create_request("manual/monitor/users?job_id=#{job_id.inner_text}&format=xml")
      with_silence do
        response = Server.execute(request)
      end
      xml = Hpricot(response.body)
      status = (xml/"status")
      percent_complete = (xml/"percent_complete")
      if status && percent_complete
        percent_complete = percent_complete.inner_text
        status = status.inner_text
        completed = "100" == percent_complete
        unless silent
          logger.info("#{percent_complete}% complete")
          puts("#{percent_complete}% complete")
        end
        sleep(POLLING_INTERVAL) unless completed
      else
        logger.debug("Missing status and percent complete in #{response.body}")
        failures += 1
        if failures > RETRY_THRESHOLD
          status = "Communication Failure"
          break
        end
      end
    end
    return status
  end

end
