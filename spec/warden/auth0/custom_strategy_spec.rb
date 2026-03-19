# frozen_string_literal: true

require 'spec_helper'
require 'rack'

describe Warden::Auth0::Strategy do
  include_context 'fixtures'

  let(:token_payload) { valid_payload }
  let(:default_sig_key_attrs) do
    {
      "kty" => "RSA",
      "use" => "sig",
      "n" => "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e" => "AQAB",
      "kid" => "default-sig-key"
    }
  end
  let(:default_jwks_response_body) { { "keys" => [default_sig_key_attrs] } }
  let(:default_faraday_response) { instance_double(Faraday::Response, body: default_jwks_response_body) }
  let(:default_faraday_connection) { instance_double(Faraday::Connection, get: default_faraday_response) }

  let(:env) { { 'HTTP_AUTHORIZATION' => 'Bearer some-token' } }
  let(:scope) { 'user' }

  describe "with a custom inherited strategy" do
    class CustomStrategy < described_class
      def user_resolver(decoded_token)
        Fixtures::User.instance
      end
    end
    
    subject { CustomStrategy.new(env, scope) }
    let(:jwks_url)           { 'https://example.auth0.com/.well-known/jwks.json' }
    
    prepend_before do  
      allow(described_class).to receive(:connection).and_return(default_faraday_connection)
    end

    before do       
      CustomStrategy.configure do |config|
        config.algorithm = 'RS256'
        config.issuer    = 'https://example.auth0.com/'
        config.aud       = 'https://api.example.com'
        config.jwks_url  = jwks_url
      end
      allow(::JWT).to receive(:decode).and_return [token_payload, {}]
    end
  

    it 'fetches JWKS from the configured URL' do
      expect(CustomStrategy.config.jwks_url).to eq(jwks_url)
      expect(CustomStrategy.config.jwks).to be_an(Array)
    end
  end
end
