#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/build/bin/site-audit-server"

# A locally built, ad-hoc signed executable is not suitable for a macOS
# LaunchDaemon. Install it in the logged-in user's LaunchAgents domain instead.
if [[ "$(uname -s)" == "Darwin" ]]; then
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "Do not run this script with sudo on macOS. Run ./install-service.sh as your normal user; it installs LaunchAgents." >&2
    exit 2
  fi
  for label in local.sitesissues.crawler local.sitesissues.analyzer local.sitesissues.renderer local.sitesissues.site-audit-server; do
    if launchctl print "system/$label" >/dev/null 2>&1; then
      echo "System LaunchDaemon $label is still installed. Run 'sudo ./uninstall-service.sh' once, then retry as your normal user." >&2
      exit 3
    fi
  done
  if [[ " ${*:-} " != *" --user "* ]]; then
    set -- --user "$@"
  fi
elif [[ "$(uname -s)" == "Linux" && " ${*:-} " != *" --user "* ]]; then
  set -- --user "$@"
fi

NEED_BUILD=false
if [[ ! -x "$BACKEND" ]]; then
  NEED_BUILD=true
fi
if [[ "$(uname -s)" == "Darwin" ]]; then
  for binary in site-crawler site-analyzer site-renderer site-audit-server obscura obscura-worker; do
    [[ -f "$ROOT/build/bin/$binary" ]] || continue
    if [[ ! -x "$ROOT/build/bin/$binary" ]] ||
      ! codesign --verify --strict "$ROOT/build/bin/$binary" >/dev/null 2>&1; then
      NEED_BUILD=true
    fi
  done
fi

if [[ "$NEED_BUILD" == true ]]; then
  bash "$ROOT/build.sh"
fi

"$BACKEND" install-services "$@"
