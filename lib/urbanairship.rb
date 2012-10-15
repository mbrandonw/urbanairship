require 'json'
require 'net/https'
require 'time'

require File.join(File.dirname(__FILE__), 'urbanairship/response')

module Urbanairship
  begin
    require 'system_timer'
    Timer = SystemTimer
  rescue LoadError
    require 'timeout'
    Timer = Timeout
  end

  class << self
    attr_accessor :push_server
    attr_accessor :production_application_key, :production_application_secret, :production_master_secret
    attr_accessor :development_application_key, :development_application_secret, :development_master_secret
    attr_accessor :logger, :request_timeout, :provider
    attr_accessor :delivery_method, :delivered_notifications, :registered_devices

    def application_key=(key)
      @development_application_key = key
      @production_application_key = key
    end

    def application_key(options = {})
      options[:push_server] == :development ? @development_application_key : @production_application_key
    end

    def application_secret=(secret)
      @development_application_secret = secret
      @production_application_secret = secret
    end

    def application_secret(options = {})
      options[:push_server] == :development ? @development_application_secret : @production_application_secret
    end

    def master_secret=(secret)
      @development_master_secret = secret
      @production_master_secret = secret
    end

    def master_secret(options = {})
      options[:push_server] == :development ? @development_master_secret : @production_master_secret
    end

    def register_device(device_token, options = {})
      @registered_devices << options.merge(:device_token => device_token) if @delivery_method == :test

      body = parse_register_options(options).to_json

      if (options[:provider] || @provider) == :android
        do_request(:put, "/api/apids/#{device_token}", :body => body, :authenticate_with => :application_secret, :push_server => options[:push_server])
      else
        do_request(:put, "/api/device_tokens/#{device_token}", :body => body, :authenticate_with => :application_secret, :push_server => options[:push_server])
      end
    end

    def unregister_device(device_token, options = {})
      if (options[:provider] || @provider) == :android
        do_request(:delete, "/api/apids/#{device_token}", :authenticate_with => :application_secret, :push_server => options[:push_server])
      else
        do_request(:delete, "/api/device_tokens/#{device_token}", :authenticate_with => :application_secret, :push_server => options[:push_server])
      end
    end

    def delete_scheduled_push(param, options = {})
      path = param.is_a?(Hash) ? "/api/push/scheduled/alias/#{param[:alias].to_s}" : "/api/push/scheduled/#{param.to_s}"
      do_request(:delete, path, :authenticate_with => :master_secret, :push_server => options[:push_server])
    end

    def push(options = {})
      @delivered_notifications << options if @delivery_method == :test

      push_server = options.delete(:push_server)
      body = parse_push_options(options).to_json
      do_request(:post, "/api/push/", :body => body, :authenticate_with => :master_secret, :push_server => push_server)
    end

    def batch_push(notifications = [], options = {})
      @delivered_notifications += notifications if @delivery_method == :test

      body = notifications.map{|notification| parse_push_options(notification)}.to_json
      do_request(:post, "/api/push/batch/", :body => body, :authenticate_with => :master_secret, :push_server => options[:push_server])
    end

    def broadcast_push(options = {})
      @delivered_notifications << options if @delivery_method == :test

      body = parse_push_options(options).to_json
      do_request(:post, "/api/push/broadcast/", :body => body, :authenticate_with => :master_secret, :push_server => options[:push_server])
    end

    def feedback(time, options = {})
      do_request(:get, "/api/device_tokens/feedback/?since=#{format_time(time)}", :authenticate_with => :master_secret, :push_server => options[:push_server])
    end

    def delivery_method=(delivery_method)
      @delivery_method = delivery_method
      if delivery_method == :test
        @delivered_notifications = []
        @registered_devices = []
      end
    end

    private

    def do_request(http_method, path, options = {})
      return if @delivery_method == :test

      verify_configuration_values([:application_key, options[:authenticate_with]], :push_server => options[:push_server])

      klass = Net::HTTP.const_get(http_method.to_s.capitalize)

      request = klass.new(path)
      request.basic_auth application_key(options), self.send(options[:authenticate_with], options)
      request.add_field "Content-Type", "application/json"
      request.body = options[:body] if options[:body]

      Timer.timeout(request_timeout) do
        start_time = Time.now
        response = http_client.request(request)
        log_request_and_response(request, response, Time.now - start_time)
        Urbanairship::Response.wrap(response)
      end
    rescue Timeout::Error
      unless logger.nil?
        logger.error "Urbanairship request timed out after #{request_timeout} seconds: [#{http_method} #{request.path} #{request.body}]"
      end
      Urbanairship::Response.wrap(nil, :body => {:error => 'Request timeout'}, :code => '503')
    end

    def verify_configuration_values(symbols, options = {})
      absent_values = symbols.select{|symbol| self.send(symbol, options).nil? }
      raise("Must configure #{absent_values.join(", ")} before making this request.") unless absent_values.empty?
    end

    def http_client
      Net::HTTP.new("go.urbanairship.com", 443).tap{|http| http.use_ssl = true}
    end

    def parse_register_options(hash = {})
      hash[:alias] = hash[:alias].to_s unless hash[:alias].nil?
      hash
    end

    def parse_push_options(hash = {})
      hash[:schedule_for] = hash[:schedule_for].map{|elem| process_scheduled_elem(elem)} unless hash[:schedule_for].nil?
      hash
    end

    def log_request_and_response(request, response, time)
      return if logger.nil?

      time = (time * 1000).to_i
      http_method = request.class.to_s.split('::')[-1]
      logger.info "Urbanairship (#{time}ms): [#{http_method} #{request.path}, #{request.body}], [#{response.code}, #{response.body}]"
      logger.flush if logger.respond_to?(:flush)
    end

    def format_time(time)
      time = Time.parse(time) if time.is_a?(String)
      time.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    end

    def process_scheduled_elem(elem)
      if elem.class == Hash
        elem.merge!(:scheduled_time => format_time(elem[:scheduled_time]))
      else
        format_time(elem)
      end
    end

    def request_timeout
      @request_timeout || 5.0
    end
  end
end
