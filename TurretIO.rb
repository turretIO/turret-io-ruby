#!/usr/bin/ruby

=begin
Copyright 2014 Loop Science 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
=end

require 'digest'
require 'cgi'
require 'base64'
require 'net/http'
require 'uri'
require 'time'
require 'openssl'
require 'json'

DOMAIN='https://api.turret.io'

module TurretIO
	class TurretMain
		@@domain = DOMAIN

		def initialize(key, secret)
			@key = key
			@secret = secret
		end

		def getSecret
			return Base64.decode64(@secret)
		end

		def buildStringToSign(uri, time, data=nil)
			if data != nil
				return "#{uri}#{data}#{time}"
			end
			return "#{uri}#{time}"

		end

		def buildHttpObj
			host = URI.parse(@@domain)
			http = Net::HTTP.new(host.host, host.port)
			http.use_ssl = true
			return http 
		end

		def buildRequest(uri, time, type, data=nil)
			if type == 'GET'
				request = Net::HTTP::Get.new(uri)
			end

			if type == 'POST'
				request = Net::HTTP::Post.new(uri)
				request.body = Base64.strict_encode64(data)
				request.content_type = 'text/json'
			end

			request['X-LS-Time'] = "#{time}" 
			request['X-LS-Key'] = "#{@key}"
			request['X-LS-Auth'] = Base64.strict_encode64(OpenSSL::HMAC.digest('sha512', getSecret, buildStringToSign(uri, time, data)))
			return request
		end

		def GET(uri)
			http = buildHttpObj
			time = Time.now.to_i
			request = buildRequest(uri, time, 'GET')
			response = http.request(request)
			return response
		end

		def POST(uri, data)
			http = buildHttpObj
			time = Time.now.to_i
			request = buildRequest(uri, time, 'POST', data.to_json)
			response = http.request(request)
			return response
		end
	end

	class Account < TurretMain
		def get
			response = GET("/latest/account")
			return response.body
		end

		def set(outgoing_method, options=nil)
			if outgoing_method == "turret.io"
				response = POST("/latest/account/me", {type: outgoing_method})
				puts response
			end

			if outgoing_method == "aws"
				if options.key?(:aws_access_key) && options.key?(:aws_secret_access_key)
					response = POST("/latest/account/me", {type: outgoing_method, aws: options})
				end
			end

			if outgoing_method == "smtp"
				if options.key?(:smtp_host) && options.key?(:smtp_username) && options.key?(:smtp_password)
					response = POST("/latest/account/me", {type: outgoing_method, smtp: options})
				end
			end

			return response.body
		end
	end

	class Segment < TurretMain
		def get(name)
			response = GET("/latest/segment/#{name}")
			return response.body
		end

		def create(name, attribute_map)
			response = POST("/latest/segment/#{name}", {attributes: attribute_map})
			return response.body
		end

		def update(name, attribute_map)
			response = POST("/latest/segment/#{name}", {attributes: attribute_map})
			return response.body
		end
	end

	class SegmentEmail < TurretMain
		def get(segment_name, email_id)
			response = GET("/latest/segment/#{segment_name}/email/#{email_id}")
			return response.body
		end

		def create(segment_name, subject, html_body, plain_body)
			response = POST("/latest/segment/#{segment_name}/email", {subject: subject, html: html_body, plain: plain_body})
			return response.body 
		end 

		def update(segment_name, email_id, subject, html_body, plain_body)
			response = POST("/latest/segment/#{segment_name}/email/#{email_id}", {subject: subject, html: html_body, plain: plain_body})
			return response.body 
		end

		def sendTest(segment_name, email_id, email_from, recipient)
			response = POST("/latest/segment/#{segment_name}/email/#{email_id}/sendTestEmail", {email_from: email_from, recipient: recipient})
			return response.body
		end

		def send(segment_name, email_id, email_from)
			response = POST("/latest/segment/#{segment_name}/email/#{email_id}/sendEmail", {email_from: email_from})
			return response.body
		end

	end

	class User < TurretMain

        def get(email)
            response = GET("/latest/user/#{email}")
            return response.body
        end

        def set(email, attribute_map, property_map=nil)
            if property_map != nil
                attribute_map['properies'] = property_map
            end

            response = POST("/latest/user/#{email}", attribute_map)
            return response.body
        end

	end
end
