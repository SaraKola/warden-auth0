# frozen_string_literal: true

require 'spec_helper'

describe Warden::Auth0::TokenDecoder do
  include_context 'configuration'

  describe '#call(token)' do
    let(:payload) do
      {
        'sub' => '1234567890',
        'name' => 'John Doe',
        'iat' => 1516239022,
        'jti' => 'baf1dc38-0331-40d3-b80a-60fd2c5a21c3',
        'iss' => issuer
      }
    end
    let(:valid_token) { 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJqdGkiOiJiYWYxZGMzOC0wMzMxLTQwZDMtYjgwYS02MGZkMmM1YTIxYzMiLCJpc3MiOiJodHRwczovL3Rlc3QtZGV2LmV1LmF1dGgwLmNvbS8ifQ.bohJzH8dseepETezDOs3uX6oJcwJvhQwMyWnmO8OY4E' }

    let(:invalid_token) { "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJqdGkiOiJiYWYxZGMzOC0wMzMxLTQwZDMtYjgwYS02MGZkMmM1YTIxYzMiLCJpc3MiOiJodHRwczovL3Rlc3QtZGV2LmV1LmF1dGgwLmNvbS8ifQ.iMV9ZwCkU1S6Gx8v56uA6oGiM6KLdHnaV_epUDImgHg" }

    it 'returns the payload encoded in the token' do
      expect(described_class.new.call(valid_token)).to eq(payload)
    end

    it 'raises an error if decode fails' do
      expect { described_class.new.call(invalid_token) }.to raise_error(JWT::VerificationError)
    end

    it 'raises an error if no secret is set' do
      expect { described_class.new.call(nil) }.to raise_error(JWT::DecodeError)
    end
  end
end
