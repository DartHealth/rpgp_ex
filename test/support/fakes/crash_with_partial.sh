#!/bin/sh
# Fake pgp_port decrypt ($5 is OUT): leaves OUT.partial, then dies by SIGKILL.
echo x > "$5.partial"
kill -9 $$
