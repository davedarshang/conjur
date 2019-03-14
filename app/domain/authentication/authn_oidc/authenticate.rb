require 'command_class'

module Authentication
  module AuthnOidc
    Authenticate = CommandClass.new(
        dependencies: {
            enabled_authenticators: ENV['CONJUR_AUTHENTICATORS'],
            get_oidc_client_configuration: AuthnOidc::GetOidcClientConfiguration.new,
            token_factory: OidcTokenFactory.new,
            validate_security: ::Authentication::ValidateSecurity.new,
            validate_origin: ::Authentication::ValidateOrigin.new,
            audit_event: ::Authentication::AuditEvent.new,
            decode_and_verify_id_token: ::Authentication::AuthnOidc::DecodeAndVerifyIdToken.new

        },
        inputs: %i(authenticator_input)
    ) do

      def call
        access_token(@authenticator_input)
      end

      private

      def access_token(input)
        request_body = AuthnOidc::AuthenticateRequestBody.new(input.request)

        oidc_client_configuration = @get_oidc_client_configuration.(
            redirect_uri: nil, # not needed for this request
                service_id: input.service_id,
                conjur_account: input.account
        )

        id_token_attribs = @decode_and_verify_id_token.(oidc_client_configuration.provider_uri, request_body.id_token)

        input = input.update(username: conjur_username(id_token_attribs, oidc_client_configuration.id_token_user_property))

        @validate_security.(input: input, enabled_authenticators: @enabled_authenticators)

        @validate_origin.(input: input)

        @audit_event.(input: input, success: true, message: nil)

        new_token(input)
      rescue => e
        @audit_event.(input: input, success: false, message: e.message)
        raise e
      end

      def new_token(input)
        @token_factory.signed_token(
            account: input.account,
            username: input.username
        )
      end

      def conjur_username(id_token_attribs, id_token_username_field)
        conjur_username = id_token_attribs[id_token_username_field]
        raise IdTokenFieldNotFound, id_token_username_field unless conjur_username.present?

        conjur_username
      end
    end
  end
end
