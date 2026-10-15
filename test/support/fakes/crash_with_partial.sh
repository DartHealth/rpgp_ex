#!/bin/sh
# Fake pgp_port decrypt ($5 is OUT): reads its request line like the real one, leaves
# OUT.partial, then dies by SIGKILL. Reading first means the runner's write has landed before
# the fake dies, so the write can never fail with EPIPE and the only outcome is exit 137.
read -r _request
echo x > "$5.partial"
kill -9 $$
