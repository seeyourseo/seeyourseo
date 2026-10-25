#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/build/bin/site-audit-server"

if [[ "$(uname -s)" == "Darwin" ]]; then
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    DOMAIN="system"
    SERVICE_DIR="/Library/LaunchDaemons"
  else
    DOMAIN="gui/$(id -u)"
    SERVICE_DIR="$HOME/Library/LaunchAgents"
    for label in local.sitesissues.crawler local.sitesissues.analyzer local.sitesissues.renderer local.sitesissues.site-audit-server; do
      if launchctl print "system/$label" >/dev/null 2>&1; then
        echo "System LaunchDaemon $label requires elevated privileges. Run 'sudo ./uninstall-service.sh' in Terminal." >&2
        exit 2
      fi
    done
  fi

  for label in local.sitesissues.site-audit-server local.sitesissues.analyzer local.sitesissues.renderer local.sitesissues.crawler; do
    PLIST="$SERVICE_DIR/$label.plist"
    if launchctl print "$DOMAIN/$label" >/dev/null 2>&1; then
      launchctl bootout "$DOMAIN" "$PLIST"
      echo "Stopped $label"
    fi
    if [[ -e "$PLIST" ]]; then
      rm -f "$PLIST"
      echo "Removed $PLIST"
    fi
  done
  exit 0
fi

if [[ ! -x "$BACKEND" ]]; then
  echo "Service manager binary not found. Run ./build.sh first." >&2
  exit 1
fi

if [[ "$(uname -s)" == "Linux" && " ${*:-} " != *" --user "* ]]; then
  set -- --user "$@"
fi

"$BACKEND" uninstall-services "$@"
