require "telismo/version"
require "rest_client"

module Telismo
  # Your code goes here...

  	@api_base = "127.0.0.1:3000/api/v1/"

	class << self
		attr_accessor :api_key, :api_base, :api_version
	end

  	def self.createCall(params)
  		puts "AX"
  	end

  	def self.api_url(method='')
  		"http://#{self.api_key}:@#{@api_base}#{method}"
  	end

  	class Calls
  		def self.create(params)

  			url = Telismo.api_url 'test'

  			response = RestClient.post url, params

  			puts response.to_str
  		end
  	end
end
