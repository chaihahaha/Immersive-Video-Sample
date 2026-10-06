#!/bin/bash
#
# Build the FFmpeg wasm static libraries that the player links against --
# natively on this machine with the local emsdk. No Docker, no OrbStack.
#
# WHY THIS EXISTS
# ---------------
# The libraries in ~/source/ffmpeg_wasm_lib were produced by the Dockerfile in
# ~/source/ffmpeg.wasm, which does `FROM emscripten/emsdk:3.1.40` and builds
# inside a Linux container. That was inherited from the ffmpeg.wasm project's own
# build system, not a requirement of the output: emcc runs natively on macOS, and
# x264, x265 and FFmpeg each use their own hand-written configure (or CMake), so
# neither autoconf nor GNU libtool is involved. The one thing the toolchain does
# need is that the objects carry the `atomics` and `bulk-memory` target features,
# because the player links them into a -pthread (shared-memory) WebAssembly
# module -- that is what -matomics -mbulk-memory below is for.
#
# This script reproduces the container's stages directly:
#   x264 (branch 4-cores) -> x265 (3.4, 3 variants merged) -> FFmpeg n5.1.4
# with only the pieces the player actually uses enabled.
#
# Usage:
#   tools/build_ffmpeg_wasm.sh [options]
#
#   --prefix DIR    where to install include/ and lib/
#                   default: <repo>/build/ffmpeg-wasm/prefix
#   --work DIR      where to clone and build the sources
#                   default: <repo>/build/ffmpeg-wasm/src
#   --jobs N        parallelism for make/cmake (default: number of CPUs)
#   --with-x265     also build libx265. OFF by default, because the player only
#                   DECODES HEVC and libx265 is an encoder it never references;
#                   it is also by far the slowest part of the build. x265 3.4
#                   additionally pins CMake policies that CMake 4 refuses, so
#                   this option applies a small patch to its CMakeLists (logged
#                   when it happens). Pair it with -DIVS_FFMPEG_WITH_X265=ON.
#   --clean         remove the work directory first
#   -h, --help
#
# Both prefixes are under build/, which .gitignore already excludes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="$REPO_ROOT/build/ffmpeg-wasm/prefix"
WORK="$REPO_ROOT/build/ffmpeg-wasm/src"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
WITH_X265=0   # the player only decodes HEVC; see --with-x265
CLEAN=0

# The mirror the ffmpeg.wasm Dockerfile uses (and that emsdk was cloned through).
# Override with GITHUB_MIRROR= if you prefer direct github.com.
MIRROR="${GITHUB_MIRROR:-https://ghfast.top/github.com}"

X264_BRANCH="4-cores"
X265_BRANCH="3.4"
FFMPEG_VERSION="n5.1.4"

usage() { sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)  PREFIX="$2"; shift 2 ;;
    --work)    WORK="$2"; shift 2 ;;
    --jobs)    JOBS="$2"; shift 2 ;;
    --with-x265) WITH_X265=1; shift ;;
    --clean)   CLEAN=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
# 0. Toolchain
# ---------------------------------------------------------------------------
if ! command -v emcc >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  source "$HOME/source/emsdk/emsdk_env.sh"
fi
command -v emcc >/dev/null 2>&1 || { echo "emcc not found; source emsdk_env.sh first" >&2; exit 1; }

# emsdk_env.sh sets EM_CACHE itself, so this must come after sourcing it.
export EM_CACHE="${EM_CACHE:-$REPO_ROOT/.emcache}"
mkdir -p "$EM_CACHE"

INSTALL_DIR="$PREFIX"
export FFMPEG_VERSION

# -matomics -mbulk-memory: required, see the note at the top of this file. The
# resulting objects must report these target features or the player's link fails
# with "--shared-memory is disallowed ... not compiled with 'atomics'".
export CFLAGS="-I$INSTALL_DIR/include -matomics -mbulk-memory"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-L$INSTALL_DIR/lib -matomics -mbulk-memory"
export EM_PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig:$EMSDK/upstream/emscripten/system/lib/pkgconfig"
export PKG_CONFIG_PATH="$EM_PKG_CONFIG_PATH"
export EM_TOOLCHAIN_FILE="$EMSDK/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake"

[ "$CLEAN" = "1" ] && rm -rf "$WORK"
mkdir -p "$WORK" "$PREFIX"

say "emcc: $(emcc --version | head -1)"
echo "prefix : $PREFIX"
echo "work   : $WORK"
echo "jobs   : $JOBS"
echo "x265   : $([ "$WITH_X265" = 1 ] && echo yes || echo "no (decode-only; pass --with-x265 to add it)")"

clone() {  # clone <url> <dir> <ref>
  local url="$1" dir="$2" ref="$3"
  if [ -d "$dir/.git" ]; then
    echo "  $dir already cloned"
    return
  fi
  rm -rf "$dir"
  git clone --depth 1 --branch "$ref" "$url" "$dir"
}

# ---------------------------------------------------------------------------
# 1. x264
# ---------------------------------------------------------------------------
say "x264 ($X264_BRANCH)"
if [ -f "$INSTALL_DIR/lib/libx264.a" ]; then
  echo "  already installed, skipping (use --clean to force)"
else
clone "$MIRROR/ffmpegwasm/x264.git" "$WORK/x264" "$X264_BRANCH"
cd "$WORK/x264"
# --host=x86-gnu mirrors the container's flags; x264's configure only uses it to
# pick sensible defaults, the real compiler is emcc.
emconfigure ./configure \
  --prefix="$INSTALL_DIR" \
  --host=x86-gnu \
  --enable-static \
  --disable-cli \
  --disable-asm \
  --extra-cflags="$CFLAGS"
emmake make install-lib-static -j"$JOBS"
fi

# ---------------------------------------------------------------------------
# 2. x265 (optional)
# ---------------------------------------------------------------------------
if [ "$WITH_X265" = "1" ]; then
  say "x265 ($X265_BRANCH) -- three variants, this is the slow part"
  clone "$MIRROR/ffmpegwasm/x265.git" "$WORK/x265" "$X265_BRANCH"
  cd "$WORK/x265/source"
  rm -rf build && mkdir -p build/main build/10bit build/12bit

  # x265 3.4 pins CMP0025/CMP0054 to OLD; CMake 4 removed that ability and
  # aborts. Drop those two lines. Only touches the fetched copy under build/.
  if emcmake cmake --version 2>/dev/null | head -1 | grep -q 'version 4\.'; then
    if grep -q 'cmake_policy(SET CMP0025 OLD)\|cmake_policy(SET CMP0054 OLD)' CMakeLists.txt; then
      echo "  patching x265 CMakeLists.txt for CMake 4 (drops CMP0025/CMP0054 OLD)"
      sed -i.bak -e '/cmake_policy(SET CMP0025 OLD)/d' \
                -e '/cmake_policy(SET CMP0054 OLD)/d' CMakeLists.txt
    fi
  fi


  # -DCMAKE_POLICY_VERSION_MINIMUM: x265 3.4 predates CMake 3.5 and CMake 4
  # refuses to configure it otherwise.
  BASE=(-DCMAKE_TOOLCHAIN_FILE="$EM_TOOLCHAIN_FILE" -DENABLE_LIBNUMA=OFF
        -DENABLE_SHARED=OFF -DENABLE_CLI=OFF
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5)

  (
    cd build/12bit
    emmake cmake ../.. -DCMAKE_CXX_FLAGS="$CXXFLAGS" "${BASE[@]}" \
      -DHIGH_BIT_DEPTH=ON -DEXPORT_C_API=OFF -DMAIN12=ON
    emmake make -j"$JOBS"
  )
  (
    cd build/10bit
    emmake cmake ../.. -DCMAKE_CXX_FLAGS="$CXXFLAGS" "${BASE[@]}" \
      -DHIGH_BIT_DEPTH=ON -DEXPORT_C_API=OFF
    emmake make -j"$JOBS"
  )
  (
    cd build/main
    ln -sf ../10bit/libx265.a libx265_main10.a
    ln -sf ../12bit/libx265.a libx265_main12.a
    emmake cmake ../.. -DCMAKE_CXX_FLAGS="$CXXFLAGS" "${BASE[@]}" \
      -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
      -DEXTRA_LIB="x265_main10.a;x265_main12.a" \
      -DEXTRA_LINK_FLAGS=-L. -DLINKED_10BIT=ON -DLINKED_12BIT=ON
    emmake make -j"$JOBS"
    mv libx265.a libx265_main.a
    emar -M <<'EOF'
CREATE libx265.a
ADDLIB libx265_main.a
ADDLIB libx265_main10.a
ADDLIB libx265_main12.a
SAVE
END
EOF
    emmake make install -j"$JOBS"
  )
fi

# ---------------------------------------------------------------------------
# 3. FFmpeg
# ---------------------------------------------------------------------------
say "FFmpeg ($FFMPEG_VERSION)"
clone "$MIRROR/FFmpeg/FFmpeg.git" "$WORK/FFmpeg" "$FFMPEG_VERSION"
cd "$WORK/FFmpeg"

ENABLE=(--enable-gpl --enable-libx264)
[ "$WITH_X265" = "1" ] && ENABLE+=(--enable-libx265)

emconfigure ./configure \
  --prefix="$INSTALL_DIR" \
  --target-os=none \
  --arch=x86_32 \
  --enable-cross-compile \
  --disable-asm \
  --disable-stripping \
  --disable-programs \
  --disable-doc \
  --disable-debug \
  --disable-runtime-cpudetect \
  --disable-autodetect \
  --nm=emnm --ar=emar --ranlib=emranlib \
  --cc=emcc --cxx=em++ --objcc=emcc --dep-cc=emcc \
  --extra-cflags="$CFLAGS" \
  --extra-cxxflags="$CXXFLAGS" \
  "${ENABLE[@]}"

emmake make -j"$JOBS"
emmake make install

# ---------------------------------------------------------------------------
# 4. Report
# ---------------------------------------------------------------------------
say "done"
echo "installed into $PREFIX"
ls -la "$PREFIX/lib" | head -20
echo
echo "Configure the player against it with:"
echo "  -DIVS_FFMPEG_WASM_LIB_DIR=$PREFIX"
[ "$WITH_X265" = "0" ] && echo "  -DIVS_FFMPEG_WITH_X265=OFF"
