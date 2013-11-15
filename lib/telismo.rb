require "telismo/version"
require "rest_client"
require "base64"

module Telismo
  # Your code goes here...

  @api_base = "telismo.com/api/v1/"
  @ssl_bundle_path  = File.dirname(__FILE__) + '/data/ca-certificates.crt'
  @verify_ssl_certs = true

	class << self
		attr_accessor :api_key, :api_base, :api_version, :verify_ssl_certs
	end
	
  def self.api_url(method='')
		"https://#{self.api_key}:@#{@api_base}#{method}"
	end

  def self.file_readable(file)
    begin
      File.open(file) { |f| }
    rescue
      false
    else
      true
    end
  end

	def self.process_callback(request)
		JSON.parse request.body.read
	end

  def self.request_headers(api_key)
    headers = {
      :user_agent => "Telismo/v1 RubyBindings/#{Telismo::VERSION}",
      :content_type => 'application/x-www-form-urlencoded'
    }

    headers[:telismo_version] = api_version if api_version

  end

  def self.execute_request(name, payload, method)
    
    url = Telismo.api_url name

    unless api_key ||= @api_key
      raise 'No API key provided. ' +
        'Set your API key using "Telismo.api_key = <API-KEY>". ' +
        'You can generate API keys from the Telismo admin interface on your dashboard at the top right corner. '
    end

    if api_key =~ /\s/
      raise 'Your API key is invalid, as it contains spaces'
    end

    request_opts = { :verify_ssl => false }

    if ssl_preflight_passed?
      request_opts.update(:verify_ssl => OpenSSL::SSL::VERIFY_PEER,
                          :ssl_ca_file => @ssl_bundle_path)
    end

    request_opts.update(:headers => request_headers(api_key),
                          :method => method, :open_timeout => 30,
                          :payload => payload, :url => url, :timeout => 80)

    begin
      RestClient::Request.execute(request_opts)
    rescue SocketError => e
      raise 'Error connecting to Telismo'
    rescue RestClient::ExceptionWithResponse => e
      if rcode = e.http_code and rbody = e.http_body
        raise 'API Error'
      else
        handle_restclient_error(e)
      end
    rescue RestClient::Exception, Errno::ECONNREFUSED => e
      handle_restclient_error(e)
    end

  end

  def self.getBalance
    response = Telismo::execute_request("balance",{}, "GET")

    JSON.parse(response.to_str)
  end

	class Calls

		def self.create(params)

      payload = {
        :number => params[:number],
        :name => params[:name],
        :instruction => {
          :text => params[:description],
          :sample => params[:sample]
        },
        :fields_b64 => Base64.strict_encode64(params[:fields].to_json),
        :type => params[:type],
        :callback => params[:callback]
      }

			response = Telismo::execute_request("create",payload, "POST")

			JSON.parse(response.to_str)
		end

    def self.quote(params)

      payload = {
        :number => params[:number],
        :name => params[:name],
        :instruction => {
          :text => params[:description],
          :sample => params[:sample]
        },
        :fields_b64 => Base64.strict_encode64(params[:fields].to_json),
        :type => params[:type]
      }

      response = Telismo::execute_request("quote",payload, "POST")

      JSON.parse(response.to_str)
    end

    def self.list(params = {})
      payload = {}

      payload[:from] = params[:from] if params[:from] 
      payload[:to] = params[:to] if params[:to] 

      response = Telismo::execute_request("list", payload, "POST")
      JSON.parse(response.to_str)
    end

    def self.cancel(params)
      payload = {
        'id' => params,
      }
      response = Telismo::execute_request("cancel", payload, "POST")
      JSON.parse(response.to_str)
    end

    def self.fetch(params)
      response = Telismo::execute_request("fetch/#{params}", {}, "GET")
      JSON.parse(response.to_str)[0]
    end
	end

    def self.handle_restclient_error(e)
      case e
        when RestClient::ServerBrokeConnection, RestClient::RequestTimeout
          message = "Could not connect to Stripe (#{@api_base}). " +
            "Please check your internet connection and try again. " +
            "If this problem persists, you should check Stripe's service status at " +
            "https://twitter.com/stripestatus, or let us know at support@stripe.com."

        when RestClient::SSLCertificateNotVerified
          message = "Could not verify Stripe's SSL certificate. " +
            "Please make sure that your network is not intercepting certificates. " +
            "(Try going to https://api.stripe.com/v1 in your browser.) " +
            "If this problem persists, let us know at support@stripe.com."

        when SocketError
          message = "Unexpected error communicating when trying to connect to Stripe. " +
            "You may be seeing this message because your DNS is not working. " +
            "To check, try running 'host stripe.com' from the command line."

        else
          message = "Unexpected error communicating with Stripe. " +
            "If this problem persists, let us know at support@stripe.com."

        end

        raise APIConnectionError.new(message + "\n\n(Network error: #{e.message})")
    end

    private

    def self.ssl_preflight_passed?
      if !verify_ssl_certs && !@no_verify
        $stderr.puts "WARNING: Running without SSL cert verification. " +
          "Execute 'Telismo.verify_ssl_certs = true' to enable verification."

        @no_verify = true

      elsif !file_readable(@ssl_bundle_path) && !@no_bundle
        $stderr.puts "WARNING: Running without SSL cert verification " +
          "because #{@ssl_bundle_path} isn't readable"

        @no_bundle = true
      end

      !(@no_verify || @no_bundle)
    end

end
