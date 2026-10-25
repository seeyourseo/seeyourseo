#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT/build"
BIN_DIR="$BUILD_DIR/bin"

export CARGO_TARGET_DIR="$BUILD_DIR/cargo-target"

mkdir -p "$BIN_DIR"

replace_binary() {
  local source="$1"
  local destination="$2"
  local temporary="${destination}.new.$$"
  cp "$source" "$temporary"
  chmod 755 "$temporary"
  mv -f "$temporary" "$destination"
}

cargo build --release --locked --manifest-path "$ROOT/services/site-crawler/Cargo.toml"
cargo build --release --locked --manifest-path "$ROOT/services/site-analyzer/Cargo.toml"
cargo build --release --locked --manifest-path "$ROOT/services/site-renderer/Cargo.toml"
cargo build --release --locked --manifest-path "$ROOT/backend/Cargo.toml"

# Build Obscura from a pinned upstream source tag. Its default render feature
# includes the native browser engine without the optional stealth transport.
OBSCURA_SOURCE="$ROOT/third_party/obscura"
if [[ ! -f "$OBSCURA_SOURCE/Cargo.toml" ]]; then
  mkdir -p "$(dirname "$OBSCURA_SOURCE")"
  git clone --depth 1 --branch v0.2.5 https://github.com/h4ckf0r0day/obscura.git "$OBSCURA_SOURCE"
fi
cargo build --release --locked --manifest-path "$OBSCURA_SOURCE/Cargo.toml" \
  -p obscura-cli --bins --features render

replace_binary "$CARGO_TARGET_DIR/release/site-crawler" "$BIN_DIR/site-crawler"
replace_binary "$CARGO_TARGET_DIR/release/site-analyzer" "$BIN_DIR/site-analyzer"
replace_binary "$CARGO_TARGET_DIR/release/site-renderer" "$BIN_DIR/site-renderer"
replace_binary "$CARGO_TARGET_DIR/release/site-audit-server" "$BIN_DIR/site-audit-server"
replace_binary "$CARGO_TARGET_DIR/release/obscura" "$BIN_DIR/obscura"
if [[ -f "$CARGO_TARGET_DIR/release/obscura-worker" ]]; then
    replace_binary "$CARGO_TARGET_DIR/release/obscura-worker" "$BIN_DIR/obscura-worker"
fi

# Rust's macOS linker emits an ad-hoc signature. AMFI may kill such binaries
# when launchd starts them as services, so sign each shipped executable with a
# real local Apple signing identity. Set CODESIGN_IDENTITY to choose one.
if [[ "$(uname -s)" == "Darwin" ]]; then
  SIGNING_IDENTITIES=()
  if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    SIGNING_IDENTITIES=("$CODESIGN_IDENTITY")
  else
    while IFS= read -r identity; do
      SIGNING_IDENTITIES+=("$identity")
    done < <(
      security find-identity -v -p codesigning |
        awk '/valid identities found/ { exit } /^[[:space:]]*[0-9]+\)/ { print $2 }'
    )
  fi
  if [[ "${#SIGNING_IDENTITIES[@]}" -eq 0 ]]; then
    echo "No valid Apple code-signing identity found. Set CODESIGN_IDENTITY and rebuild." >&2
    exit 1
  fi

  for binary in site-crawler site-analyzer site-renderer site-audit-server obscura obscura-worker; do
    [[ -f "$BIN_DIR/$binary" ]] || continue
    SIGNED=false
    for identity in "${SIGNING_IDENTITIES[@]}"; do
      if codesign --force --sign "$identity" --timestamp=none "$BIN_DIR/$binary" &&
        codesign --verify --strict "$BIN_DIR/$binary" >/dev/null 2>&1; then
        SIGNED=true
        break
      fi
    done
    if [[ "$SIGNED" != true ]]; then
      echo "Could not produce a trusted signature for $binary. Set CODESIGN_IDENTITY to a trusted Apple identity and rebuild." >&2
      exit 1
    fi
  done
fi

# Linux keeps the sandbox launchers in dedicated directories. The renderer
# can execute these workers without gaining execute access to sibling services.
if [[ "$(uname -s)" == "Linux" ]]; then
  mkdir -p "$BIN_DIR/sandbox/obscura"
  ln -f "$BIN_DIR/obscura" "$BIN_DIR/sandbox/obscura/obscura"
fi

rm -f "$BIN_DIR/openseo-site-crawler" "$BIN_DIR/openseo-site-analyzer" "$BIN_DIR/openseo-web" "$BIN_DIR/backend"

printf 'Build complete. Binaries: %s\n' "$BIN_DIR"
