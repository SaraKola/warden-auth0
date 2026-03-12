# frozen_string_literal: true

shared_context 'configuration' do
  before do
    Warden::Auth0.configure do |config|
      config.token_header = 'Authorization'
    end

    Warden::Auth0::Strategy.reset_resolved_jwks!
    Warden::Auth0::Strategy.configure do |config|
      config.issuer = 'https://test-dev.eu.auth0.com/'
      config.aud = 'https://test.com/api'
      config.algorithm = "RS256"
      config.jwks_url = "https://my-url.com/.well-known/jwks.json"
      config.jwks = {}
      config.verify_ssl = true
    end

    Warden::Strategies.add(:auth0, Warden::Auth0::Strategy) do
      def user_resolver(decoded_token)
        Fixtures::User.instance
      end
    end
  end

  let(:config) { Warden::Auth0::Strategy.config }
  let(:token_header) { Warden::Auth0.config.token_header }
  let(:issuer) { config.issuer }
  let(:env_token_header) { ('HTTP_' + Warden::Auth0.config.token_header.upcase).tr('-', '_') }
end
