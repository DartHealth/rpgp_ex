#!/bin/sh
# Fake pgp_port decrypt ($5 is OUT): leaves OUT.partial, then records its pid (so the pid file
# proves OUT.partial exists), then hangs.
echo x > "$5.partial"
echo $$ > "$5.pid"
exec sleep 30
