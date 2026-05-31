#!/usr/bin/env sh
# ============================================================================
# gen-assets.sh — regenerate raster brand assets from the committed SVG sources
# ============================================================================
# SealWard (S34L-W4RD) ships ONLY SVG sources under branding/ and
# .github/assets/. This script rasterizes them on demand into the git-ignored
# PNG/ICO/ICNS/BMP outputs that a release or an OS package would reference:
#
#   * social-preview.png  1280x640  (GitHub OG card, from social-preview.svg)
#   * icon-256.png        256x256   (from icon.svg — the signing seal glyph)
#   * icon.ico            multi-res 16..256 (Windows, from icon.svg)
#   * icon.icns           Apple iconset     (macOS, from icon.svg)
#
# Tooling is free OSS: librsvg's rsvg-convert OR ImageMagick's convert for SVG
# rasterization; ImageMagick for .ico; iconutil (macOS) / png2icns elsewhere
# for .icns. If a tool is missing, the script PRINTS THE EXACT INSTALL COMMAND
# and SKIPS that output honestly — it never writes a corrupt or placeholder
# asset, and it never fakes success.
#
# Usage:
#   ./gen-assets.sh            # rasterize every output it can
#   ./gen-assets.sh --help
# ----------------------------------------------------------------------------
set -eu

while [ $# -gt 0 ]; do
  case "$1" in
    -h | --help)
      echo "Usage: $0   (rasterizes branding/ + .github/assets/ SVG sources)"
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

BRANDING="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(CDPATH='' cd -- "$BRANDING/.." && pwd)"
ASSETS="$REPO/.github/assets"

ICON_SVG="$BRANDING/icon.svg"
SOCIAL_SVG="$ASSETS/social-preview.svg"

if [ ! -f "$ICON_SVG" ]; then
  echo "ERROR: icon source not found: $ICON_SVG" >&2
  exit 1
fi

# --- Pick an SVG rasterizer. ---
RASTER=""
if command -v rsvg-convert >/dev/null 2>&1; then
  RASTER="rsvg"
elif command -v convert >/dev/null 2>&1; then
  RASTER="im"
else
  echo "NOTICE: no SVG rasterizer found (need librsvg's rsvg-convert or" >&2
  echo "        ImageMagick's convert). Install one of:" >&2
  echo "          apt-get install librsvg2-bin      # rsvg-convert" >&2
  echo "          brew install librsvg              # rsvg-convert" >&2
  echo "          apt-get install imagemagick       # convert" >&2
  echo "Skipping raster generation (no asset faked)." >&2
  exit 0
fi

svg_to_png() {
  # $1 = src svg, $2 = dst png, $3 = width, $4 = height
  if [ "$RASTER" = "rsvg" ]; then
    rsvg-convert -w "$3" -h "$4" "$1" -o "$2"
  else
    convert -background none -resize "${3}x${4}" "$1" "$2"
  fi
}

# --- Social-preview OG card (1280x640) ---
if [ -f "$SOCIAL_SVG" ]; then
  echo "==> Generating social-preview.png (1280x640)"
  svg_to_png "$SOCIAL_SVG" "$ASSETS/social-preview.png" 1280 640
fi

# --- App icon PNG (256x256) ---
echo "==> Generating icon-256.png (256x256)"
svg_to_png "$ICON_SVG" "$BRANDING/icon-256.png" 256 256

# --- Windows .ico (multi-resolution) ---
if command -v convert >/dev/null 2>&1; then
  echo "==> Generating Windows .ico"
  TMPDIR_ICO="$(mktemp -d)"
  for sz in 16 32 48 64 128 256; do
    svg_to_png "$ICON_SVG" "$TMPDIR_ICO/icon-$sz.png" "$sz" "$sz"
  done
  convert "$TMPDIR_ICO"/icon-*.png "$BRANDING/icon.ico"
  rm -rf "$TMPDIR_ICO"
else
  echo "NOTICE: ImageMagick 'convert' absent — .ico skipped (install imagemagick)." >&2
fi

# --- macOS .icns ---
if command -v iconutil >/dev/null 2>&1; then
  echo "==> Generating macOS .icns (iconutil)"
  ICONSET="$(mktemp -d)/icon.iconset"
  mkdir -p "$ICONSET"
  for sz in 16 32 64 128 256 512; do
    svg_to_png "$ICON_SVG" "$ICONSET/icon_${sz}x${sz}.png" "$sz" "$sz"
    dbl=$((sz * 2))
    svg_to_png "$ICON_SVG" "$ICONSET/icon_${sz}x${sz}@2x.png" "$dbl" "$dbl"
  done
  iconutil -c icns "$ICONSET" -o "$BRANDING/icon.icns"
elif command -v png2icns >/dev/null 2>&1; then
  echo "==> Generating macOS .icns (png2icns)"
  TMPDIR_ICNS="$(mktemp -d)"
  for sz in 16 32 48 128 256 512; do
    svg_to_png "$ICON_SVG" "$TMPDIR_ICNS/icon-$sz.png" "$sz" "$sz"
  done
  png2icns "$BRANDING/icon.icns" "$TMPDIR_ICNS"/icon-*.png
  rm -rf "$TMPDIR_ICNS"
else
  echo "NOTICE: no .icns tool (iconutil on macOS / png2icns elsewhere) — .icns skipped." >&2
fi

echo "==> Asset generation complete."
