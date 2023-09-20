module GrapeDeviseTokenAuth
  class AuthorizerData
    attr_reader :uid, :client_id, :token, :expiry, :warden

    def initialize(authorization, uid, client_id, token, expiry, warden)
      decoded_authorization_token = decode_bearer_token(authorization)

      @uid = uid || decoded_authorization_token['uid']
      @client_id = decoded_authorization_token['client']
      @token = token || decoded_authorization_token['access-token']
      @expiry = expiry || decoded_authorization_token['expiry']
      @warden = warden
    end

    def self.from_env(env)
      new(
        env[Configuration::AUTHORIZATION],
        env[Configuration::UID_KEY],
        env[Configuration::CLIENT_KEY] || 'default',
        env[Configuration::ACCESS_TOKEN_KEY],
        env[Configuration::EXPIRY_KEY],
        env['warden']
      )
    end

    def token_prerequisites_present?
      token && uid
    end

    def decode_bearer_token(bearer_token)
      return {} if bearer_token.blank?

      encoded_token = bearer_token.split.last # Removes the 'Bearer' from the string
      JSON.parse(Base64.strict_decode64(encoded_token)) rescue {}
    end
  end
end
