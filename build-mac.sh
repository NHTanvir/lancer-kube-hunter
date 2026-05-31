#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
BUILD="$REPO/build"
BIN="lancer-kube-hunter"

echo "================================================"
echo "  lancer-kube-hunter Build (macOS)"
echo "================================================"
echo ""
echo "  Repo   : $REPO"
echo "  Output : $BUILD/$BIN"
echo ""

echo "[1/3] Building release binary..."
cargo build --release

echo "[2/3] Copying to build/..."
mkdir -p "$BUILD"
cp "$REPO/target/release/$BIN" "$BUILD/"

echo "[3/3] Bundling .app (optional)..."
if command -v cargo-bundle >/dev/null 2>&1; then
    cargo bundle --release || echo "  (cargo bundle failed — binary is still available)"
    echo "  .app bundle: target/release/bundle/osx/"
else
    echo "  cargo-bundle not installed; skipping .app packaging."
    echo "  Install with: cargo install cargo-bundle"
fi

echo ""
echo "================================================"
echo "  Done!  Binary ready: $BUILD/$BIN"
echo "  Double-click to open the GUI, or run with --cli for the terminal surface."
echo "================================================"
