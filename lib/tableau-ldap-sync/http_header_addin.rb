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

require 'net/http'

module Net
  HTTPResponse.class_eval do
    # If a single cookie is set more than once, this will return the first
    # value.  I'm not sure what the RFC actually says, but this will
    # work for our purposes
    def get_cookie(name)
      cookies = get_fields('set-cookie')
      unless cookies
        return nil 
      end
      cookies.each do |line|
        kv = line.split(';')[0] # Gets rid of path, etc
        key, val = kv.split('=')
        return val if key == name        
      end
      nil
    end
  end

  HTTPRequest.class_eval do
    def set_cookie(name, newval)
      old_cookies = get_fields('cookie')
      found = false
      if old_cookies
        delete('cookie')  # clear old the old cookies; we'll add them back
        old_cookies.each do |line|
          fields = line.split(';')
          key = fields[0].split('=')[0]
          if key == name
            fields[0] = [key, newval].join('=')
            line = fields.join(';')
            found = true
          end
          add_field('cookie', line)
        end
      end
      add_field('cookie', [name, newval].join('=')) unless found
    end
  end
end

if not Net::HTTP.method_defined? :orig_request
  module Net
    class HTTP
      
      alias :orig_request :request
  
      def request(req, body = nil, &block)
        if not body.nil? and body.respond_to? :read
          req.body_stream = body
          return orig_request(req, nil, &block)
        else
          return orig_request(req, body, &block)
        end
      end
    end
    
    class HTTPResponse
      def body_stream=(f)
        @body = f
      end
      
      def is_stream?
        @body.respond_to? :read
      end
    end

  end
end