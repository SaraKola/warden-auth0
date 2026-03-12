# frozen_string_literal: true

require 'dry/configurable'
require 'jwt'
require 'warden'
require 'faraday'

module Warden
  # Auth0 authentication plugin for warden.
  #
  # It consists of a strategy which tries to authenticate an user decoding a
  # token present in the request header (as `Bearer %token%`). The header name
  # is configured via +token_header+.
  module Auth0
    extend Dry::Configurable

    # Request header used for receiving and returning the token.
    setting :token_header, default: 'Authorization'

    setting :verify_ssl, default: true

    # Fetches JWKS from the given URL. Used by the strategy when jwks_url is configured.
    def self.fetch_jwks(jwks_url)
      raise 'No url provided for fetching jwks' if jwks_url.nil?

      jwks_response = connection.get(jwks_url).body
      jwks = JWT::JWK::Set.new(jwks_response)
      jwks.select { |key| key[:use] == 'sig' }
    rescue StandardError => e
      raise "Failed to fetch JWKS: #{e.message}"
    end

    def self.connection
      Faraday.new(request: { timeout: 5 }, ssl: { verify: config.verify_ssl }) do |conn|
        conn.response :json
      end
    end
  end
end

require 'warden/auth0/version'
require 'warden/auth0/errors'
require 'warden/auth0/header_parser'
require 'warden/auth0/env_helper'
require 'warden/auth0/token_decoder'
require 'warden/auth0/strategy'
