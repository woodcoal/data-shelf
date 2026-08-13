#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${DIST_DIR:-"$ROOT_DIR/dist"}
GO_BIN=${GO_BIN:-go}
VERSION_FILE="$ROOT_DIR/VERSION"

cd "$ROOT_DIR"

if [[ ! -f "$VERSION_FILE" ]]; then
  echo "VERSION file is required" >&2
  exit 1
fi

RELEASE_VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")
if [[ ! "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "VERSION must contain a numeric semantic version; found: $RELEASE_VERSION" >&2
  exit 1
fi

RELEASE_TAG="v$RELEASE_VERSION"
ARTIFACT_PREFIX="datashelf-$RELEASE_TAG"
CHECKSUMS_FILE="SHA256SUMS-$RELEASE_TAG"
LINUX_AMD64_ARTIFACT="$ARTIFACT_PREFIX-linux-amd64"
DARWIN_AMD64_ARTIFACT="$ARTIFACT_PREFIX-darwin-amd64"
DARWIN_ARM64_ARTIFACT="$ARTIFACT_PREFIX-darwin-arm64"
WINDOWS_AMD64_ARTIFACT="$ARTIFACT_PREFIX-windows-amd64.exe"

if [[ -n "${GITHUB_REF_NAME:-}" && "$GITHUB_REF_NAME" == v* && "${GITHUB_REF_NAME#v}" != "$RELEASE_VERSION" ]]; then
  echo "Git tag $GITHUB_REF_NAME does not match VERSION $RELEASE_VERSION" >&2
  exit 1
fi

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
  "$DIST_DIR/$LINUX_AMD64_ARTIFACT" \
  "$DIST_DIR/$DARWIN_AMD64_ARTIFACT" \
  "$DIST_DIR/$DARWIN_ARM64_ARTIFACT" \
  "$DIST_DIR/$WINDOWS_AMD64_ARTIFACT" \
  "$DIST_DIR/$CHECKSUMS_FILE"

build_target() {
  local goos=$1
  local goarch=$2
  local output=$3

  echo "Building $output ($goos/$goarch)"
  GOOS="$goos" GOARCH="$goarch" "$GO_BIN" build \
    -trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.buildVersion=$RELEASE_VERSION" \
    -o "$DIST_DIR/$output" .
}

build_target linux amd64 "$LINUX_AMD64_ARTIFACT"
build_target darwin amd64 "$DARWIN_AMD64_ARTIFACT"
build_target darwin arm64 "$DARWIN_ARM64_ARTIFACT"
build_target windows amd64 "$WINDOWS_AMD64_ARTIFACT"

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

check_artifact "$LINUX_AMD64_ARTIFACT" linux
check_artifact "$DARWIN_AMD64_ARTIFACT" darwin
check_artifact "$DARWIN_ARM64_ARTIFACT" darwin
check_artifact "$WINDOWS_AMD64_ARTIFACT" windows

if [[ "$(uname -s)" == "Linux" ]] && command -v ldd >/dev/null 2>&1; then
  LDD_OUTPUT=$(ldd "$DIST_DIR/$LINUX_AMD64_ARTIFACT" 2>&1 || true)
  if ! grep -qi 'not a dynamic executable' <<<"$LDD_OUTPUT"; then
    echo "$LINUX_AMD64_ARTIFACT is dynamically linked" >&2
    exit 1
  fi
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DIST_DIR" && sha256sum \
    "$LINUX_AMD64_ARTIFACT" \
    "$DARWIN_AMD64_ARTIFACT" \
    "$DARWIN_ARM64_ARTIFACT" \
    "$WINDOWS_AMD64_ARTIFACT" > "$CHECKSUMS_FILE")
else
  (cd "$DIST_DIR" && shasum -a 256 \
    "$LINUX_AMD64_ARTIFACT" \
    "$DARWIN_AMD64_ARTIFACT" \
    "$DARWIN_ARM64_ARTIFACT" \
    "$WINDOWS_AMD64_ARTIFACT" > "$CHECKSUMS_FILE")
fi

echo "DataShelf $RELEASE_VERSION release artifacts written to $DIST_DIR"
ls -lh "$DIST_DIR"
