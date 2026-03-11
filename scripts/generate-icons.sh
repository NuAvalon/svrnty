#!/bin/bash
# Generate PWA icons from SVG source
# Requires: Inkscape or ImageMagick (convert)
#
# Usage: ./scripts/generate-icons.sh
#
# This script converts the SVG icons to PNG at the required PWA sizes.
# If you don't have the tools installed:
#   sudo apt install inkscape
#   — or —
#   sudo apt install imagemagick
#
# Alternatively, create icon-192.png and icon-512.png manually using any
# image editor. The manifest.json expects them in /public/.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PUBLIC_DIR="$SCRIPT_DIR/../public"

# Check for SVG sources
if [ ! -f "$PUBLIC_DIR/icon-192.svg" ] && [ ! -f "$PUBLIC_DIR/icon-512.svg" ]; then
  echo "No SVG source icons found in $PUBLIC_DIR"
  echo "Create icon-192.svg and icon-512.svg first, then re-run this script."
  exit 1
fi

# Try Inkscape first, fall back to ImageMagick
if command -v inkscape &> /dev/null; then
  echo "Using Inkscape..."
  if [ -f "$PUBLIC_DIR/icon-512.svg" ]; then
    inkscape "$PUBLIC_DIR/icon-512.svg" -w 192 -h 192 -o "$PUBLIC_DIR/icon-192.png"
    inkscape "$PUBLIC_DIR/icon-512.svg" -w 512 -h 512 -o "$PUBLIC_DIR/icon-512.png"
  else
    inkscape "$PUBLIC_DIR/icon-192.svg" -w 192 -h 192 -o "$PUBLIC_DIR/icon-192.png"
    inkscape "$PUBLIC_DIR/icon-192.svg" -w 512 -h 512 -o "$PUBLIC_DIR/icon-512.png"
  fi
elif command -v convert &> /dev/null; then
  echo "Using ImageMagick..."
  if [ -f "$PUBLIC_DIR/icon-512.svg" ]; then
    convert -background none -resize 192x192 "$PUBLIC_DIR/icon-512.svg" "$PUBLIC_DIR/icon-192.png"
    convert -background none -resize 512x512 "$PUBLIC_DIR/icon-512.svg" "$PUBLIC_DIR/icon-512.png"
  else
    convert -background none -resize 192x192 "$PUBLIC_DIR/icon-192.svg" "$PUBLIC_DIR/icon-192.png"
    convert -background none -resize 512x512 "$PUBLIC_DIR/icon-192.svg" "$PUBLIC_DIR/icon-512.png"
  fi
else
  echo "Neither Inkscape nor ImageMagick found."
  echo "Install one of them, or create icon-192.png (192x192) and icon-512.png (512x512) manually."
  exit 1
fi

echo "Icons generated:"
ls -la "$PUBLIC_DIR"/icon-*.png
