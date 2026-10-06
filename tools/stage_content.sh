#!/bin/bash
#
# Stage the Gaslamp DASH content that the player actually needs, so that
# --preload-file only bakes that subset into render.data.
#
# Why: the full package is 256 MB, of which 189 MB is AdaptationSet 1000..1049
# (OMAF extractor tracks). With <enableExtractor>0</enableExtractor> the player
# runs in LATER_BINDING mode and never touches them, so preloading them just
# wastes 189 MB of WebAssembly memory -- which matters a lot, because decoding
# 8192x4096 HEVC needs hundreds of MB of frame buffers on its own.
#
# Files are hard-linked (same filesystem assumed), so this costs no extra disk.
#
# Usage: tools/stage_content.sh [source-dir] [dest-dir]

set -euo pipefail

SRC="${1:-$HOME/source/IVS_webpage/gaslamp}"
DEST="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/webcontent}"

if [ ! -d "$SRC/Gaslamp" ]; then
  echo "source content not found: $SRC/Gaslamp" >&2
  exit 1
fi

mkdir -p "$DEST/Gaslamp"

echo "staging from $SRC/Gaslamp -> $DEST/Gaslamp"

# The MPD itself.
cp -f "$SRC/Gaslamp/Test.mpd" "$DEST/Gaslamp/Test.mpd"

# Tile tracks 1..36 (8x4 grid of 1024x1024 plus four 1024x512 sub-tiles):
# init segments and every numbered media segment.
linked=0
for t in $(seq 1 36); do
  for f in "$SRC/Gaslamp/Test_track$t."*.mp4; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    if [ ! -e "$DEST/Gaslamp/$b" ]; then
      ln "$f" "$DEST/Gaslamp/$b" 2>/dev/null || cp -f "$f" "$DEST/Gaslamp/$b"
    fi
    linked=$((linked + 1))
  done
done

echo "staged $linked files"
du -sh "$DEST"
