defmodule AshAuthentication.Jwt.ConfigTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Mimic
  alias AshAuthentication.{Jwt.Config, TokenResource}

  describe "default_claims/1" do
    test "it is a token config" do
      claims = Config.default_claims(Example.User)
      assert is_map(claims)

      assert Enum.all?(claims, fn {name, config} ->
               assert is_binary(name)
               assert is_struct(config, Joken.Claim)
             end)
    end

    test "token_lifetime can be provided in hours by supplying an int" do
      expected_expiry = DateTime.utc_now() |> DateTime.add(1, :hour)

      assert {:ok, %{"exp" => exp}} =
               Config.default_claims(Example.User, token_lifetime: 1)
               |> Joken.generate_claims()

      assert {:ok, expiry} = DateTime.from_unix(exp)
      assert DateTime.diff(expected_expiry, expiry, :second) |> abs() <= 2
    end

    test "token_lifetime can be provided in seconds by suppying a tuple" do
      expected_expiry = DateTime.utc_now() |> DateTime.add(30, :second)

      assert {:ok, %{"exp" => exp}} =
               Config.default_claims(Example.User, token_lifetime: {30, :second})
               |> Joken.generate_claims()

      assert {:ok, expiry} = DateTime.from_unix(exp)
      assert DateTime.diff(expected_expiry, expiry, :second) |> abs() <= 2
    end

    test "token_lifetime can be provided in minutes by suppying a tuple" do
      expected_expiry = DateTime.utc_now() |> DateTime.add(1, :minute)

      assert {:ok, %{"exp" => exp}} =
               Config.default_claims(Example.User, token_lifetime: {1, :minute})
               |> Joken.generate_claims()

      assert {:ok, expiry} = DateTime.from_unix(exp)
      assert DateTime.diff(expected_expiry, expiry, :second) |> abs() <= 2
    end

    test "token_lifetime can be provided in hours by suppying a tuple" do
      expected_expiry = DateTime.utc_now() |> DateTime.add(1, :hour)

      assert {:ok, %{"exp" => exp}} =
               Config.default_claims(Example.User, token_lifetime: {1, :hour})
               |> Joken.generate_claims()

      assert {:ok, expiry} = DateTime.from_unix(exp)
      assert DateTime.diff(expected_expiry, expiry, :second) |> abs() <= 2
    end

    test "token_lifetime can be provided in days by suppying a tuple" do
      expected_expiry = DateTime.utc_now() |> DateTime.add(1, :day)

      assert {:ok, %{"exp" => exp}} =
               Config.default_claims(Example.User, token_lifetime: {1, :day})
               |> Joken.generate_claims()

      assert {:ok, expiry} = DateTime.from_unix(exp)
      assert DateTime.diff(expected_expiry, expiry, :second) |> abs() <= 2
    end
  end

  describe "generate_issuer/1" do
    test "it correctly generates" do
      assert "AshAuthentication v1.2.3" = Config.generate_issuer(Version.parse!("1.2.3"))
    end
  end

  describe "validate_issuer/3" do
    test "is true when the issuer starts with \"AshAuthentication\"" do
      assert Config.validate_issuer("AshAuthentication foo", nil, nil)
    end

    test "is false otherwise" do
      garbage = 2 |> Faker.Lorem.words() |> Enum.join(" ")
      refute Config.validate_issuer(garbage, nil, nil)
    end
  end

  describe "generate_audience/1" do
    test "it correctly generates" do
      assert "~> 1.2" = Config.generate_audience(Version.parse!("1.2.3"))
    end
  end

  describe "validate_audience/4" do
    test "is true when the decoding version meets the minimum requirement" do
      assert Config.validate_audience("~> 1.2", nil, nil, Version.parse!("1.2.3"))
    end

    test "is false otherwise" do
      refute Config.validate_audience("~> 1.2", nil, nil, Version.parse!("1.1.2"))
    end
  end

  describe "validate_jti/3" do
    test "is true when the token has not been revoked" do
      TokenResource
      |> stub(:jti_revoked?, fn _, _ -> false end)

      assert Config.validate_jti("fake jti", nil, Example.User)
    end

    test "is false when the token has been revoked" do
      TokenResource
      |> stub(:jti_revoked?, fn _, _ -> true end)

      assert Config.validate_jti("fake jti", nil, Example.User)
    end
  end

  describe "token_signer/1" do
    test "it returns a signer configuration" do
      assert %Joken.Signer{} = Config.token_signer(Example.User)
    end
  end
end
