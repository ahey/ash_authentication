defmodule AshAuthentication.Dsl do
  @moduledoc false

  ###
  ### Only exists to move the DSL out of `AshAuthentication` to aid readability.
  ###

  import AshAuthentication.Utils, only: [to_sentence: 2]
  import Joken.Signer, only: [algorithms: 0]

  alias Ash.{Api, Resource}

  @default_token_lifetime_days 14

  alias Spark.Dsl.Section

  @doc false
  @spec secret_type :: any
  def secret_type,
    do:
      {:or,
       [
         {:spark_function_behaviour, AshAuthentication.Secret,
          {AshAuthentication.SecretFunction, 2}},
         :string
       ]}

  @doc false
  @spec secret_doc :: String.t()
  def secret_doc,
    do: """
    Takes either a module which implements the `AshAuthentication.Secret`
    behaviour, a 2 arity anonymous function or a string.

    See the module documentation for `AshAuthentication.Secret` for more
    information.
    """

  @doc false
  @spec dsl :: [Section.t()]
  def dsl do
    secret_type = secret_type()
    secret_doc = secret_doc()

    [
      %Section{
        name: :authentication,
        describe: "Configure authentication for this resource",
        modules: [:api],
        schema: [
          subject_name: [
            type: :atom,
            doc: """
            The subject name is used anywhere that a short version of your
            resource name is needed, eg:

              - generating token claims,
              - generating routes,
              - form parameter nesting.

            This needs to be unique system-wide and if not set will be inferred
            from the resource name (ie `MyApp.Accounts.User` will have a subject
            name of `user`).
            """
          ],
          api: [
            type: {:behaviour, Api},
            doc: """
            The name of the Ash API to use to access this resource when
            doing anything authenticaiton related.
            """,
            required: true
          ],
          get_by_subject_action_name: [
            type: :atom,
            doc: """
            The name of the read action used to retrieve records.

            Used internally by `AshAuthentication.subject_to_user/2`.  If the
            action doesn't exist, one will be generated for you.
            """,
            default: :get_by_subject
          ]
        ],
        sections: [
          %Section{
            name: :tokens,
            describe: "Configure JWT settings for this resource",
            modules: [:token_resource],
            schema: [
              enabled?: [
                type: :boolean,
                doc: """
                Should JWTs be generated by this resource?
                """,
                default: false
              ],
              store_all_tokens?: [
                type: :boolean,
                doc: """
                Store all tokens in the `token_resource`?

                Some applications need to keep track of all tokens issued to
                any user.  This is optional behaviour with `ash_authentication`
                in order to preserve as much performance as possible.
                """,
                default: false
              ],
              require_token_presence_for_authentication?: [
                type: :boolean,
                doc: """
                Require a locally-stored token for authentication?

                This inverts the token validation behaviour from requiring that
                tokens are not revoked to requiring any token presented by a
                client to be present in the token resource to be considered
                valid.

                Requires `store_all_tokens?` to be `true`.
                """,
                default: false
              ],
              signing_algorithm: [
                type: :string,
                doc: """
                The algorithm to use for token signing.

                Available signing algorithms are;
                #{to_sentence(algorithms(), final: "and")}.
                """,
                default: hd(algorithms())
              ],
              token_lifetime: [
                type: :pos_integer,
                doc: """
                How long a token should be valid, in hours.

                Since refresh tokens are not yet supported, you should
                probably set this to a reasonably long time to ensure
                a good user experience.

                Defaults to #{@default_token_lifetime_days} days.
                """,
                default: @default_token_lifetime_days * 24
              ],
              token_resource: [
                type: {:or, [{:behaviour, Resource}, {:in, [false]}]},
                doc: """
                The resource used to store token information.

                If token generation is enabled for this resource, we need a place to
                store information about tokens, such as revocations and in-flight
                confirmations.
                """,
                required: true
              ],
              signing_secret: [
                type: secret_type,
                doc: """
                The secret used to sign tokens.

                #{secret_doc}
                """
              ]
            ]
          },
          %Section{
            name: :strategies,
            describe: "Configure authentication strategies on this resource",
            entities: [],
            patchable?: true
          },
          %Section{
            name: :add_ons,
            describe: "Additional add-ons related to, but not providing authentication",
            entities: [],
            patchable?: true
          }
        ]
      }
    ]
  end
end
