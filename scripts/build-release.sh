#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${DIST_DIR:-"$ROOT_DIR/dist"}
GO_BIN=${GO_BIN:-go}

cd "$ROOT_DIR"

if ! command -v "$GO_BIN" >/dev/null 2>&1; then
  echo "Go 1.25 or newer is required" >&2
  exit 1
fi

GO_VERSION=$($GO_BIN version)
read -r GO_MAJOR GO_MINOR < <(printf '%s\n' "$GO_VERSION" | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\1 \2/')
if [[ -z "${GO_MAJOR:-}" || -z "${GO_MINOR:-}" ]] || (( GO_MAJOR < 1 || (GO_MAJOR == 1 && GO_MINOR < 25) )); then
  echo "Go 1.25 or newer is required; found: $GO_VERSION" >&2
  exit 1
fi

export GOFLAGS=-mod=readonly
export CGO_ENABLED=0

echo "Using $GO_VERSION"
echo "Downloading and verifying modules"
"$GO_BIN" mod download
"$GO_BIN" mod verify

echo "Running tests with CGO_ENABLED=0"
"$GO_BIN" test ./...

mkdir -p "$DIST_DIR"
rm -f \
  "$DIST_DIR/datashelf-linux-amd64" \
  "$DIST_DIR/datashelf-darwin-amd64" \
  "$DIST_DIR/datashelf-darwin-arm64" \
  "$DIST_DIR/datashelf-windows-amd64.exe" \
  "$DIST_DIR/SHA256SUMS"

build_target() {
  local goos=$1
  local goarch=$2
  local output=$3

  echo "Building $output ($goos/$goarch)"
  GOOS="$goos" GOARCH="$goarch" "$GO_BIN" build \
    -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$DIST_DIR/$output" .
}

build_target linux amd64 datashelf-linux-amd64
build_target darwin amd64 datashelf-darwin-amd64
build_target darwin arm64 datashelf-darwin-arm64
build_target windows amd64 datashelf-windows-amd64.exe

check_artifact() {
  local artifact=$1
  local kind=$2

  test -s "$DIST_DIR/$artifact"
  if command -v file >/dev/null 2>&1; then
    local description
    description=$(file -b "$DIST_DIR/$artifact")
    case "$kind" in
      linux)
        grep -Eq 'ELF .*executable' <<<"$description"
        grep -qi 'statically linked' <<<"$description"
        ;;
      darwin)
        grep -q 'Mach-O 64-bit .* executable' <<<"$description"
        ;;
      windows)
        grep -q 'PE32+ executable' <<<"$description"
        ;;
    esac
  fi
}

check_artifact datashelf-linux-amd64 linux
check_artifact datashelf-darwin-amd64 darwin
check_artifact datashelf-darwin-arm64 darwin
check_artifact datashelf-windows-amd64.exe windows

if [[ "$(uname -s)" == "Linux" ]] && command -v ldd >/dev/null 2>&1; then
  LDD_OUTPUT=$(ldd "$DIST_DIR/datashelf-linux-amd64" 2>&1 || true)
  if ! grep -qi 'not a dynamic executable' <<<"$LDD_OUTPUT"; then
    echo "datashelf-linux-amd64 is dynamically linked" >&2
    exit 1
  fi
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DIST_DIR" && sha256sum datashelf-* > SHA256SUMS)
else
  (cd "$DIST_DIR" && shasum -a 256 datashelf-* > SHA256SUMS)
fi

echo "Release artifacts written to $DIST_DIR"
ls -lh "$DIST_DIR"
