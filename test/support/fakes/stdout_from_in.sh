#!/bin/sh
# Fake pgp_port recipients ($3 is IN): prints IN as its stdout, exits with the status in IN.status.
cat "$3"
exit "$(cat "$3.status")"
