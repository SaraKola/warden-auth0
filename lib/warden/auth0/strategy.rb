# frozen_string_literal: true

require 'warden'

module Warden
  module Auth0
    # Warden strategy to authenticate a user through a JWT token in the
    # `Authorization` request header
    class Strategy < Warden::Strategies::Base
      def valid?
        token_exists? && issuer_claim_valid? && aud_claim_valid?
      end

      def store?
        false
      end

      def authenticate!
        raise Errors::WrongIssuer, 'wrong issuer' unless issuer_claim_valid?
        raise Errors::WrongAud, 'wrong audience' unless aud_claim_valid?

        resolver_method = "#{scope}_resolver"
        raise "unimplemented resolver #{resolver_method}" unless respond_to?(resolver_method)

        user = send(resolver_method, decoded_token)
        raise Warden::Auth0::Errors::NilUser, 'nil user' unless user

        success!(user)
      rescue JWT::DecodeError => e
        puts "Failing to authenticate with #{e.message}"
        fail!(e.message)
      end

      private

      def token
        @token ||= HeaderParser.from_env(env)
      end

      def token_exists?
        !token.nil?
      end

      def decoded_token
        TokenDecoder.new.call(token)
      end

      def issuer_claim_valid?
        issuer = configured_issuer
        issuer_matches?(decoded_token, issuer)
      rescue JWT::DecodeError
        false
      end

      def aud_claim_valid?
        audience = configured_aud
        audience_matches?(decoded_token, audience)
      rescue JWT::DecodeError
        false
      end

      def configured_aud
        audience = Warden::Auth0.config.aud
        raise Errors::NoConfiguredAud if audience.nil?

        audience
      end

      def configured_issuer
        configured_issuer = Warden::Auth0.config.issuer
        raise Errors::NoConfiguredIssuer if configured_issuer.nil?

        configured_issuer
      end

      def issuer_matches?(payload, issuer_config)
        token_issuer = payload['iss'].to_s
        return false unless token_issuer

        if issuer_config.is_a?(String)
          return token_issuer == issuer_config.to_s
        elsif issuer_config.is_a?(Array)
          return issuer_config.map(&:to_s).include?(token_issuer)
        end

        false
      end

      def audience_matches?(payload, issuer_aud)
        token_audience = payload['aud']
        return false unless token_audience

        if issuer_aud.is_a?(String)
          return true if token_audience == issuer_aud.to_s
          return token_audience.is_a?(Array) && token_audience.include?(issuer_aud)
        elsif issuer_aud.is_a?(Array)
          return true if issuer_aud.include?(token_audience)
          return token_audience.is_a?(Array) && (token_audience & issuer_aud).any?
        end

        false
      end
    end
  end
end
