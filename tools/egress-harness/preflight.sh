#!/bin/sh
set -eu

# Fail closed: do not start a collector unless an isolated network namespace is
# available. The Phase 1 packet assertions are deliberately not run in the host
# namespace.
if ! command -v unshare >/dev/null 2>&1; then
    echo "BLOCKED: unshare is unavailable; no egress assertions were run" >&2
    exit 77
fi
if ! unshare --net true 2>/dev/null; then
    echo "BLOCKED: network namespace creation is not permitted; no egress assertions were run" >&2
    exit 77
fi
echo "READY: isolated namespace available; harness packet assertions are not yet implemented"
exit 2
