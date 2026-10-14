# mix compile has already built pgp_port from this checkout into priv/bin (config/config.exs).
ExUnit.start(exclude: [:gpg_agent, :large])
