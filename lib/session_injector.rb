require 'active_support/message_encryptor'
require 'uri'

module Rack
  module Middleware
    class SessionInjector

      class InvalidHandshake < StandardError; end

      RACK_COOKIE_STRING = 'rack.request.cookie_string'.freeze
      RACK_COOKIE_HASH = 'rack.request.cookie_hash'.freeze
      HTTP_COOKIE = 'HTTP_COOKIE'.freeze

      DEFAULT_OPTIONS = {
        # use the AbstractStore default key as our session id key
        # if you have configured a custom session store key, you must
        # specify that as the value for this middleware
        :key => ActionDispatch::Session::AbstractStore::DEFAULT_OPTIONS[:key],
        :token_lifetime => 5, # five seconds should be enough
        :die_on_handshake_failure => true
      }

      # the env key we will use to stash ourselves for downstream access
      SESSION_INJECTOR_KEY = '_session_injector';
      # the env key upstream uses to stash a flag to tell us to propagate a session
      # this is a convenience for manually adding a request parameter to a redirect response location
      SESSION_PROPAGATE_KEY = '_session_propagate';

      # the internal parameter we will use to convey the session handshake token
      HANDSHAKE_PARAM = '_hs_';

      def initialize(app, options = {})
        @app = app
        options = DEFAULT_OPTIONS.merge(options)
        @session_id_key = options[:key]
        # statically generated token key in case we
        # need to fall back (no cookie token key has been set)
        # handshakes are by definition transient, so the only
        # important requirement is that the middleware that generates
        # the token can decrypt the token. when not under a clustered/balanced
        # architecture, that most likely means the same process/middelware
        # so the key value is not important
        # in fact, non-durability of the token is a security feature
        generated_token_key = SecureRandom.random_bytes(16).unpack("H*")[0]
        @token_key = options[:token_key] || generated_token_key
        @enforced_lifetime = options[:token_lifetime]
        @die_on_handshake_failure = options[:die_on_handshake_failure]
      end

      def call(env)
        env[SESSION_INJECTOR_KEY] = self; # store ourselves for downstream access
        reconstitute_session(env)
        response = @app.call(env)
        response = propagate_session(env, *response)
        response
      end

      # rewrites location header if requested
      def propagate_session(env, status, headers, response)
        propagate_flag = env.delete(SESSION_PROPAGATE_KEY)
        location = headers["Location"]
        if propagate_flag and location
          # we've been told to rewrite the location header and it is present
          uri = URI::parse(location)
          prefix = uri.query ? "&" : ""
          # append handshake param to query
          uri.query = [uri.query, prefix, SessionInjector.generate_handshake_parameter(Rack::Request.new(env), propagate_flag[0], propagate_flag[1])].join
          headers["Location"] = uri.to_s
        end
        [ status, headers, response]
      end

      # generates the handshake token we can send to the target domain
      def self.generate_handshake_token(request, target_domain, lifetime = nil)
        # retrieve the configured middleware instance
        session_injector = request.env[SESSION_INJECTOR_KEY]
        # note: scheme is not included in handshake
        # a session initiated on https may be established on http
        handshake = {
          :request_ip => request.ip,
          :request_path => request.fullpath, # more for accounting/stats than anything else
          :src_domain => request.host,
          :tgt_domain => target_domain,
          :token_create_time => Time.now.to_i,
          # the most important thing
          :session_id => extract_session_id(request, session_injector.session_id_key)
        }
        handshake[:requested_lifetime] = lifetime if lifetime
        # we could reuse ActionDispatch::Cookies.TOKEN_KEY if it is present but let's not!
        ActiveSupport::MessageEncryptor.new(session_injector.token_key).encrypt_and_sign(handshake);
      end

      # generates the handshake parameter key=value string
      def self.generate_handshake_parameter(request, target_domain, lifetime = nil)
        "#{HANDSHAKE_PARAM}=#{generate_handshake_token(request, target_domain, lifetime)}"
      end

      # helper that sets a flag to rewrite the location header with session propagation handshake
      def self.propagate_session(request, target_domain, lifetime = nil)
        request.env[SESSION_PROPAGATE_KEY] = [ target_domain, lifetime ]
      end

      # find the current session id
      def self.extract_session_id(request, session_id_key)
        #request.session_options[:id]
        request.cookies[session_id_key]
      end

      # return the env key containing the session id
      def session_id_key
        @session_id_key
      end

      # return the key we use for encryption and hashing
      def token_key
        @token_key
      end

      protected

      # validates the handshake against the current environment
      def validate_handshake(handshake, env)
        # is the handshake token expired?
        token_create_time = handshake[:token_create_time]
        raise InvalidHandshake, "token creation time missing" unless token_create_time
        now = Time.now.to_i
        token_age = now - token_create_time
        raise InvalidHandshake, "token has is expired" unless token_age < @enforced_lifetime
        # ok, we can accept this token, but does the source want us to?
        raise InvalidHandshake, "token has outlived requested expiration" if handshake[:requested_lifetime] and token_age > handshake[:requested_lifetime]

        # cool, token is not expired
        # is it for the right domain?
        this_request = Rack::Request.new(env)
        raise InvalidHandshake, "target domain mismatch" unless handshake[:tgt_domain] == this_request.host

        # it's FOR the right domain
        # is it FROM the right domain?
        # SKIP THIS CHECK
        # 'referrer' is not reliable, is up to the client to send, and we may not always be coming from a redirect
        # raise InvalidHandshake, "source domain mismatch" unless handshake[:src_domain] == URI::parse(this_request.referrer).host

        # finally, is this the same client that was associated with the source session?
        # this really should be the case unless some shenanigans is going on (either somebody is replaying the token
        # or there is some client balancing or proxying going on)
        raise InvalidHandshake, "client ip mismatch" unless handshake[:request_ip] == this_request.ip
      end

      private

      # load and inject any session that might be conveyed in this request
      def reconstitute_session(env)
        request = Rack::Request.new(env)
        token = request.params[HANDSHAKE_PARAM]
        return unless token

        # decrypt the token and get the session cookie value
        handshake = decrypt_handshake_token(token, env)
        return unless handshake

        cookie_value = handshake[:session_id]

        # fix up Rack env
        # ensure the cookie string is set
        env[HTTP_COOKIE] = [env[HTTP_COOKIE], "#{@session_id_key}=#{cookie_value}"].compact.join(';')
        # Rack request object parses cookies on demand and stores data in internal env keys
        # but the current implementation is not good about writing back through to the env
        # Since requests objects are transient wrappers we have to be prepared to encounter an env
        # that may already be initialized with some state
        # if the cookie string has already been read by Rack, update Rack's internal cookie string variable
        if env[RACK_COOKIE_STRING]
          env[RACK_COOKIE_STRING] = [env[RACK_COOKIE_STRING], "#{@session_id_key}=#{cookie_value}"].compact.join(';')
        end
        # if the cookie string has already been read by Rack, update Rack's internal cookie hash variable
        request = Rack::Request.new(env)
        request.cookies[@session_id_key] = cookie_value # call cookies() to make Rack::Request do its stuff
      end

      # decrypts a handshake token sent to us from a source domain
      def decrypt_handshake_token(token, env)
        handshake = ActiveSupport::MessageEncryptor.new(@token_key).decrypt_and_verify(token);
        begin
          validate_handshake(handshake, env)
          return handshake
        rescue InvalidHandshake
          raise if @die_on_handshake_failure
        end
        return nil
      end
    end
  end
end
