import Config

# Developing rpgp_ex itself: build pgp_port from this checkout, never download a release.
# A library's config is not loaded by the projects that depend on it.
config :rpgp_ex, build_from_source: true
