# Warden::Auth0

`warden-auth0` is a [Warden](https://github.com/hassox/warden) extension that authenticates users using [JWT](https://jwt.io/) tokens issued by [Auth0](https://auth0.com/) (or any OIDC-compatible provider). It validates tokens using the provider’s JWKS endpoint and enforces issuer and audience claims.

This gem only handles **verification** of existing tokens. It does not issue or revoke tokens. Sign-in and sign-out (and refresh tokens, if needed) are handled by your Auth0 integration (e.g. frontend SDK or API).

## Installation

```ruby
gem 'warden-auth0'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install warden-auth0

## Usage

At its core, this library provides:

- A Warden strategy that authenticates a user when a valid JWT is present in the request (e.g. `Authorization: Bearer <token>`).
- Token verification using JWKS (no shared secret): algorithm, issuer, and audience are validated.

### Configuration

Configure the main module and the strategy before adding it to Warden.

**1. Warden::Auth0 (global)**

```ruby
Warden::Auth0.configure do |config|
  config.token_header = 'Authorization'  # request header used for the Bearer token (default: 'Authorization')
end
```

**2. Warden::Auth0::Strategy (issuer, audience, JWKS)**

You must set `issuer`, `aud`, and either `jwks_url` or `jwks`. The strategy will verify the JWT signature using the provider’s public keys (JWKS).

```ruby
Warden::Auth0::Strategy.configure do |config|
  config.issuer   = 'https://your-tenant.eu.auth0.com/'
  config.aud      = 'https://your-api.com'                    # or an array of allowed audiences
  config.algorithm = 'RS256'
  config.jwks_url = 'https://your-tenant.eu.auth0.com/.well-known/jwks.json'
  # config.jwks   = nil   # optional: set a JWT::JWK::Set if you don't want to use jwks_url
  config.verify_ssl = true  # default: true
end
```

- **issuer**: Expected `iss` claim (string or array of strings).
- **aud**: Expected `aud` claim (string or array of allowed values).
- **algorithm**: JWT algorithm (e.g. `RS256`).
- **jwks_url**: URL to the JWKS document; keys are fetched and used to verify the token signature.
- **jwks**: Optional. A `JWT::JWK::Set` instance; if set, `jwks_url` is not used.
- **verify_ssl**: Whether to verify SSL when fetching JWKS (default: `true`).

**3. Add the strategy to Warden with a scope resolver**

For each Warden scope you use with this strategy, you must define a resolver method named `#{scope}_resolver`. It receives the decoded token (hash) and must return the user object for that scope, or `nil` to fail authentication.

```ruby
Warden::Strategies.add(:auth0, Warden::Auth0::Strategy) do
  def user_resolver(decoded_token)
    sub = decoded_token['sub']
    User.find_by(auth0_id: sub)
  end
end
```

If you use multiple scopes (e.g. `:user` and `:admin`), define both resolvers:

```ruby
Warden::Strategies.add(:auth0, Warden::Auth0::Strategy) do
  def user_resolver(decoded_token)
    User.find_by(auth0_id: decoded_token['sub'])
  end

  def admin_resolver(decoded_token)
    Admin.find_by(auth0_id: decoded_token['sub'])
  end
end
```

**4. Enable the strategy for your scopes**

In your Warden configuration (e.g. in Rails):

```ruby
config.warden.default_strategies scope: :user, strategies: [:auth0]
# and for admin scope, if used:
config.warden.default_strategies scope: :admin, strategies: [:auth0]
```

### Request authentication

Send the JWT in the configured request header (default `Authorization`) as:

```
Authorization: Bearer <your-jwt>
```

The strategy will:

1. Parse the token from the header.
2. Validate `iss` and `aud` against the configured issuer and audience.
3. Verify the signature using JWKS from `jwks_url` (or the provided `jwks`).
4. Call the appropriate `#{scope}_resolver` with the decoded payload and set the user on success.

### Multiple issuers

You can allow tokens from more than one issuer by passing an array:

```ruby
Warden::Auth0::Strategy.configure do |config|
  config.issuer = ['https://tenant-a.auth0.com/', 'https://tenant-b.auth0.com/']
  # ...
end
```

### Errors

The strategy may raise or use:

- `Warden::Auth0::Errors::NoConfiguredIssuer` – `issuer` not configured.
- `Warden::Auth0::Errors::NoConfiguredAud` – `aud` not configured.
- `Warden::Auth0::Errors::WrongIssuer` – token `iss` does not match.
- `Warden::Auth0::Errors::WrongAud` – token `aud` does not match.
- `Warden::Auth0::Errors::NilUser` – resolver returned `nil`.
- `JWT::DecodeError` (and subclasses) – invalid or malformed token.

## Development

There are Docker and docker-compose files configured for the development environment. If you use Docker:

```bash
docker-compose up -d
docker-compose exec app rspec
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sarakola/warden-auth0. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
