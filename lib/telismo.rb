require "telismo/version"
require "rest_client"
require "base64"

module Telismo
  # Your code goes here...

  	@api_base = "telismo.com/api/v1/"

	class << self
		attr_accessor :api_key, :api_base, :api_version
	end

  	def self.createCall(params)
  		puts "AX"
  	end

  	def self.api_url(method='')
  		"http://#{self.api_key}:@#{@api_base}#{method}"
  	end

  	def self.process_callback(request)
  		JSON.parse request.body.read
  	end

  	class Calls
  		def self.create(params)

  			url = Telismo.api_url 'create'


  			response = RestClient.post url, {
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

  			JSON.parse(response.to_str)
  		end
  	end
end
