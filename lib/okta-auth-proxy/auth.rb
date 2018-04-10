require 'sinatra/base'
require 'omniauth'
require 'omniauth-saml'
require 'securerandom'

module OktaAuthProxy
  module OktaAuth

    COOKIE_DOMAIN = ENV['COOKIE_DOMAIN'] || 'localhost'

    module AuthHelpers
      def protected!
        return if authorized?(request.host)
        redirect to("/auth/saml?redirectUrl=#{URI::encode(request.path)}")
      end

      def authorized?(host)
        if session[:uid]
          return ENV['PROXY_TARGET']
        else
          return false
        end
      end
    end

    def self.registered(app)
      app.helpers OktaAuthProxy::OktaAuth::AuthHelpers

      # Use a wildcard cookie to achieve single sign-on for all subdomains
      app.use Rack::Session::Cookie, secret: ENV['COOKIE_SECRET'] || SecureRandom.random_bytes(24),
                                     domain: COOKIE_DOMAIN
      app.use OmniAuth::Builder do
        provider :saml,
        issuer:                             ENV['SSO_ISSUER'],
        idp_sso_target_url:                 ENV['SSO_TARGET_URL'],
        idp_cert:                           File.read( ENV['CERT_PATH'] || 'okta_cert.pem'),
        name_identifier_format:             "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        idp_sso_target_url_runtime_params:  {:redirectUrl => :RelayState}
      end
    end
  end
end
