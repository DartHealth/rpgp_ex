#!/bin/sh
# Fake pgp_port: closes stdin unread, then exits a moment later. Once stdin has no reader, a
# payload larger than the pipe buffer must fail with EPIPE, whichever event the port sees first.
exec 0<&-
sleep 0.2
exit 1
