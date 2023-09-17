defmodule AshAuthentication.GenerateTokenChange do
  @moduledoc """
  Given a successful registration or sign-in, generate a token.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.{Info, Jwt}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, options, context) do
    changeset
    |> Changeset.after_action(fn changeset, result ->
      {:ok, strategy} = Info.find_strategy(changeset, context, options)

      if Info.authentication_tokens_enabled?(result.__struct__) do
        {:ok, generate_token(changeset.context[:token_type] || :user, result, strategy)}
      else
        {:ok, result}
      end
    end)
  end

  defp generate_token(purpose, record, strategy)
       when purpose in [:user, :sign_in] and is_integer(strategy.sign_in_token_lifetime) do
    {:ok, token, _claims} =
      Jwt.token_for_user(record, %{"purpose" => to_string(purpose)},
        token_lifetime: strategy.sign_in_token_lifetime
      )

    Ash.Resource.put_metadata(record, :token, token)
  end

  defp generate_token(purpose, record, _strategy) do
    {:ok, token, _claims} = Jwt.token_for_user(record, %{"purpose" => to_string(purpose)})

    Ash.Resource.put_metadata(record, :token, token)
  end
end
