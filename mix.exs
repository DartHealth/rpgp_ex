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
      deps: deps(),
      description: "OpenPGP encryption and decryption backed by rPGP, a pure-Rust implementation",
      package: package(),
      source_url: @source_url
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps, do: []

  defp package do
    [licenses: ["MIT", "Apache-2.0"], links: %{"GitHub" => @source_url}]
  end
end
