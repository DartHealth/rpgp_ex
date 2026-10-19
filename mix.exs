defmodule RpgpEx.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/DartHealth/rpgp_ex"

  def project do
    [
      app: :rpgp_ex,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      # :pgp_port installs the native executable once the Elixir code is compiled.
      compilers: Mix.compilers() ++ [:pgp_port],
      deps: deps(),
      description: "OpenPGP encryption and decryption backed by rPGP, a pure-Rust implementation",
      package: package(),
      source_url: @source_url,
      docs: docs()
    ]
  end

  def application do
    [
      mod: {RpgpEx.Application, []},
      # :inets, :ssl and :public_key download pgp_port at compile time only.
      extra_applications: [:logger, inets: :optional, ssl: :optional, public_key: :optional]
    ]
  end

  defp deps do
    [{:ex_doc, "~> 0.40", only: :dev, runtime: false}]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "SECURITY.md"],
      source_ref: "v#{@version}"
    ]
  end

  defp package do
    [
      licenses: ["MIT", "Apache-2.0"],
      links: %{"GitHub" => @source_url, "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"},
      # native/pgp_port is the cargo fallback; checksums-pgp_port.exs verifies the downloads.
      files: ~w(
        lib mix.exs README.md CHANGELOG.md SECURITY.md LICENSE-MIT LICENSE-APACHE checksums-pgp_port.exs
        native/pgp_port/src native/pgp_port/Cargo.toml native/pgp_port/Cargo.lock native/pgp_port/.cargo
      )
    ]
  end
end
