# frozen_string_literal: true

require 'jwt/error'

module Warden
  module Auth0
    # Decodes a JWT into a hash payload. Algorithm and JWKS are provided by the strategy config.
    class TokenDecoder
      attr_reader :algorithm, :jwks

      # @param algorithm [String] algorithm (e.g. 'RS256')
      # @param jwks [Object] JWKS used to verify (e.g. JWT::JWK::Set)
      def initialize(algorithm:, jwks:)
        @algorithm = algorithm
        @jwks = jwks
      end

      # Decodes the payload from a JWT as a hash
      #
      # @param token [String] a JWT
      # @return [Hash] payload decoded from the JWT
      def call(token)
        JWT.decode(token, nil, true, algorithms: algorithm, jwks: jwks)[0]
      end
    end
  end
end
