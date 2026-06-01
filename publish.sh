#!/usr/bin/env bash
# publish.sh - build and publish contextwall + cre-sdk to PyPI
#
# Usage:
#   ./publish.sh                  # publish current versions
#   ./publish.sh --bump patch     # bump patch version first (0.1.0 -> 0.1.1)
#   ./publish.sh --bump minor     # bump minor version (0.1.0 -> 0.2.0)
#   ./publish.sh --bump major     # bump major version (0.1.0 -> 1.0.0)
#   ./publish.sh --test           # upload to TestPyPI instead
#
# Required env:
#   PYPI_TOKEN         - PyPI API token (https://pypi.org/manage/account/token/)
#   PYPI_SDK_TOKEN     - separate token for cre-sdk (or same token if trusted publisher)
#
# Optional:
#   TESTPYPI_TOKEN     - token for test.pypi.org (used with --test)

set -euo pipefail

# ── args ──────────────────────────────────────────────────────────────────────

BUMP=""
USE_TESTPYPI=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --bump) BUMP="$2"; shift 2 ;;
    --test) USE_TESTPYPI=true; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# ── config ────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$REPO_ROOT/sdk/python"

if $USE_TESTPYPI; then
  PYPI_REPO="https://test.pypi.org/legacy/"
  TOKEN="${TESTPYPI_TOKEN:?TESTPYPI_TOKEN is required for --test}"
  SDK_TOKEN="${TESTPYPI_TOKEN}"
else
  PYPI_REPO="https://upload.pypi.org/legacy/"
  TOKEN="${PYPI_TOKEN:?PYPI_TOKEN is required}"
  SDK_TOKEN="${PYPI_SDK_TOKEN:-$TOKEN}"
fi

# ── helpers ───────────────────────────────────────────────────────────────────

bump_version() {
  local toml="$1"
  local part="$2"
  local current
  current=$(grep '^version = ' "$toml" | sed 's/version = "\(.*\)"/\1/')
  IFS='.' read -r major minor patch <<< "$current"
  case $part in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
    *) echo "Unknown bump type: $part"; exit 1 ;;
  esac
  local next="$major.$minor.$patch"
  sed -i.bak "s/^version = \"$current\"/version = \"$next\"/" "$toml"
  rm -f "$toml.bak"
  echo "$next"
}

build_and_upload() {
  local dir="$1"
  local token="$2"
  local name="$3"

  echo ""
  echo "── $name ──────────────────────────────────────────"
  cd "$dir"

  rm -rf dist/
  python -m build --wheel --sdist .

  python -m twine upload \
    --repository-url "$PYPI_REPO" \
    --username __token__ \
    --password "$token" \
    --non-interactive \
    dist/*

  echo "$name uploaded OK"
  cd "$REPO_ROOT"
}

# ── checks ────────────────────────────────────────────────────────────────────

for cmd in python twine; do
  if ! command -v $cmd &>/dev/null; then
    echo "Missing: $cmd  (pip install build twine)"
    exit 1
  fi
done

if ! python -m build --version &>/dev/null; then
  echo "Missing: python -m build  (pip install build)"
  exit 1
fi

# ── version bump ──────────────────────────────────────────────────────────────

if [[ -n "$BUMP" ]]; then
  echo "Bumping $BUMP version..."
  MAIN_VER=$(bump_version "$REPO_ROOT/pyproject.toml" "$BUMP")
  SDK_VER=$(bump_version "$SDK_DIR/pyproject.toml" "$BUMP")
  echo "  contextwall -> $MAIN_VER"
  echo "  cre-sdk     -> $SDK_VER"
fi

# ── build + upload ────────────────────────────────────────────────────────────

MAIN_VER=$(grep '^version = ' "$REPO_ROOT/pyproject.toml" | sed 's/version = "\(.*\)"/\1/')
SDK_VER=$(grep '^version = ' "$SDK_DIR/pyproject.toml" | sed 's/version = "\(.*\)"/\1/')

echo "Publishing:"
echo "  contextwall $MAIN_VER"
echo "  cre-sdk     $SDK_VER"
$USE_TESTPYPI && echo "  Target: TestPyPI" || echo "  Target: PyPI"
echo ""
read -r -p "Continue? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

build_and_upload "$REPO_ROOT"     "$TOKEN"     "contextwall $MAIN_VER"
build_and_upload "$SDK_DIR"       "$SDK_TOKEN" "contextwall-sdk $SDK_VER"

echo ""
echo "Done."
echo "  https://pypi.org/project/contextwall/$MAIN_VER/"
echo "  https://pypi.org/project/contextwall-sdk/$SDK_VER/"
