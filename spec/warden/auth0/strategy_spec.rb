# frozen_string_literal: true

require 'spec_helper'

describe Warden::Auth0::Strategy do
  include_context 'fixtures'
  include_context 'configuration'

  let(:token_payload) { valid_payload }

  let(:env) { { 'HTTP_AUTHORIZATION' => 'Bearer some-token' } }
  let(:scope) { 'user' }

  before do
    allow(::JWT).to receive(:decode).and_return [token_payload, {}]
  end

  subject { described_class.new(env, scope) }

  it 'adds Auth0::Strategy to Warden with auth0 name' do
    expect(Warden::Strategies._strategies).to include(
      auth0: described_class
    )
  end

  describe '#valid?' do
    context 'when Authorization header does not exist' do
      let(:env) { {} }

      it 'returns false' do
        expect(subject).not_to be_valid
      end
    end

    context 'when token issuer and aud match the configured ones' do
      let(:token_payload) { valid_payload }

      it 'returns true' do
        expect(subject).to be_valid
      end
    end

    context 'when token issuer does not match the configured one' do
      let(:token_payload) { wrong_iss_payload }

      it 'returns false when the token issuer does not match the configured one' do
        expect(subject).not_to be_valid
      end
    end

    context 'when token aud does not match the configured one' do
      let(:token_payload) { wrong_aud_payload }

      it 'returns false when the token aud does not match the configured one' do
        expect(subject).not_to be_valid
      end
    end
  end

  describe '#persist?' do
    it 'returns false' do
      expect(subject.store?).to eq(false)
    end
  end

  describe '#authenticate!' do
    context "when missing resolver for scope" do
      let(:scope) { 'admin' }
      let(:token_payload) { valid_payload }

      it 'raises an error' do
        expect { subject.authenticate! }.to raise_error("unimplemented resolver admin_resolver")
      end
    end

    context 'when token is invalid' do
      let(:env) { { 'HTTP_AUTHORIZATION' => 'Bearer 123' } }

      before do
        allow(::JWT)
          .to receive(:decode)
          .and_raise(JWT::VerificationError)
        subject.authenticate!
      end

      it 'fails authentication' do
        expect(subject).not_to be_successful
      end

      it 'halts authentication' do
        expect(subject).to be_halted
      end
    end

    context 'when token is valid' do
      let(:token_payload) { valid_payload }

      before { subject.authenticate! }

      it 'succeeds authentication' do
        expect(subject).to be_successful
      end

      it 'logs in user returned by current mapping' do
        expect(subject.user).to eq(user)
      end
    end

    context 'when no user is found' do
      let(:token_payload) { valid_payload }
      let(:user) { nil }

      before do
        Warden::Strategies.add(:auth0, Warden::Auth0::Strategy) do
          def user_resolver(decoded_token)
           user
          end
        end
        subject.authenticate!
      end

      it 'fails authentication' do
        expect(subject).not_to be_successful
      end

      it 'halts authentication' do
        expect(subject).to be_halted
      end
    end

    context 'when issuer does not match' do
      let(:token_payload) { wrong_iss_payload }

      before { subject.authenticate! }

      it 'fails authentication' do
        expect(subject).not_to be_successful
      end

      it 'halts authentication' do
        expect(subject).to be_halted
      end
    end

    context 'when aud does not match' do
      let(:token_payload) { wrong_aud_payload }

      before { subject.authenticate! }

      it 'fails authentication' do
        expect(subject).not_to be_successful
      end

      it 'halts authentication' do
        expect(subject).to be_halted
      end
    end
  end

  describe 'jwks setting constructor' do
    # RFC 7517 Appendix A.1 RSA public key — used as a sig key fixture
    let(:sig_key_attrs) do
      {
        "kty" => "RSA",
        "use" => "sig",
        "n"   => "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e"   => "AQAB",
        "kid" => "sig-key-1"
      }
    end

    let(:enc_key_attrs) do
      {
        "kty" => "RSA",
        "use" => "enc",
        "n"   => "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e"   => "AQAB",
        "kid" => "enc-key-1"
      }
    end

    let(:jwks_url)           { 'https://example.auth0.com/.well-known/jwks.json' }
    let(:jwks_response_body) { { "keys" => [sig_key_attrs, enc_key_attrs] } }
    let(:faraday_response)   { instance_double(Faraday::Response, body: jwks_response_body) }
    let(:faraday_connection) { instance_double(Faraday::Connection, get: faraday_response) }

    before do
      described_class.configure do |config|
        config.algorithm = 'RS256'
        config.issuer    = 'https://example.auth0.com/'
        config.aud       = 'https://api.example.com'
        config.jwks_url  = jwks_url
      end
    end

    context 'when jwks is explicitly provided' do
      let(:preset_jwks) { [instance_double(JWT::JWK::RSA)] }

      it 'stores the value as-is without making an HTTP request' do
        expect(described_class).not_to receive(:connection)
        described_class.config.jwks = preset_jwks
        expect(described_class.config.jwks).to eq(preset_jwks)
      end
    end

    context 'when jwks is nil' do
      before do
        allow(described_class).to receive(:connection).and_return(faraday_connection)
      end

      it 'fetches JWKS from the configured URL' do
        expect(faraday_connection).to receive(:get).with(jwks_url)

        expect(described_class.config.jwks_url).to eq(jwks_url)
        described_class.config.jwks = nil

        expect(described_class.config.jwks).to be_an(Array)
      end

      it 'returns only keys whose use is sig' do
        expect(described_class.config.jwks.map { |k| k[:use] }).to all(eq('sig'))
      end

      it 'excludes enc keys' do
        expect(described_class.config.jwks.none? { |k| k[:use] == 'enc' }).to be(true)
      end
    end

    context 'when jwks is nil and jwks_url is nil' do
      before { described_class.config.jwks_url = nil }

      it 'raises an error indicating the URL is missing' do
        expect { described_class.config.jwks = nil }
          .to raise_error(RuntimeError, /Failed to fetch JWKS: No url provided/)
      end
    end
  end
end
