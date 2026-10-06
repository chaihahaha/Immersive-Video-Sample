# ffmpeg.wasm build recipe (vendored)

This directory is a copy of the build recipe that produced the FFmpeg wasm static
libraries the player links against. It is here so that rebuilding them does not
require finding another checkout.

## Where it came from

Upstream: <https://github.com/ffmpegwasm/ffmpeg.wasm> (MIT, see `LICENSE`).
This copy is from the fork `git@github.com:chaihahaha/ffmpeg.wasm`, branch `main`,
commit `e2dd60e` ("new dockerfile", 2025-05-23), which is where the
modifications below were made.

Copied verbatim, with no changes:

```
Dockerfile        the modified build definition
Makefile          upstream's docker buildx wrappers
exe.sh            helper that ran the ffmpeg configure inside the container
build/*.sh        the per-library build scripts (x264, x265, ffmpeg, and the
                  ones that are commented out in the Dockerfile)
LICENSE           upstream license
```

## What was modified, and why it does not change the output

Relative to upstream `ffmpeg.wasm`, `e2dd60e`:

* pins the base image to **`emscripten/emsdk:3.1.40`**, matching the emcc used for
  the player;
* pins **`FFMPEG_VERSION=n5.1.4`**;
* keeps only **x264** and **x265**, commenting out libvpx, lame, ogg, theora,
  opus, vorbis, zlib, libwebp, freetype, fribidi, harfbuzz, libass and zimg;
* comments out the `ffmpeg-wasm-builder` and `exportor` stages, so the build
  emits **plain static libraries** and not the `ffmpeg-core.js` wrapper;
* rewrites every `ADD` URL through the `ghfast.top` GitHub mirror;
* changes `emmake make -j` to `emmake make -j 2` in `build/ffmpeg.sh`.

None of that affects the usability of the produced libraries: the trimming only
removes components the player never calls, and the mirror and `-j` change are
about fetching and build parallelism. The fork is deliberate and does **not**
need to be merged upstream.

## What is and is not vendored

**Vendored here** (everything needed to reproduce the build recipe):

* the Dockerfile, the per-library `build/*.sh`, `exe.sh`, `Makefile`, `LICENSE`.

**Not vendored, because it is upstream third-party source and about 200 MB**
(`../build_ffmpeg_wasm.sh` fetches it):

| Source | Where from | Size |
|---|---|---|
| FFmpeg `n5.1.4` | `ffmpeg/FFmpeg` | ~177 MB |
| x265 `3.4` | `ffmpegwasm/x265` | ~15 MB |
| x264 `4-cores` | `ffmpegwasm/x264` | ~12 MB |

Those are the well-known public upstreams the original Dockerfile also pulled
from, not a private fork, so nobody has to go hunting for a mystery repository.
Baking 200 MB of third-party source into git would be worse than fetching it.

**Fully offline builds are possible**: the script reuses anything already cloned
under its `--work` directory, so point `--work` at a pre-populated tree (or run
it once while online) and subsequent builds need no network.

Nothing in this repository references `~/source/ffmpeg.wasm` at runtime or at
build time. The only mentions are the provenance notes in this README and a
comment in `../build_ffmpeg_wasm.sh`.

## How to actually build (no Docker)

`../build_ffmpeg_wasm.sh` is the supported path. It performs the same stages
natively with the local emsdk:

```bash
tools/build_ffmpeg_wasm.sh --jobs 8
# or, from a configured build tree:
make ffmpeg-wasm
```

It defaults to skipping x265 (the player only decodes HEVC and references no
x265 symbol), which also sidesteps x265 3.4's CMake 4 incompatibility. Pass
`--with-x265` to include it anyway; see the script for details.

Measured: x264 + FFmpeg take about six minutes on an M4 Pro at `-j8`, and the
resulting `libx264.a` is **byte-identical** to the one the Docker build produced.

## Why the Dockerfile is kept even though it is no longer used

It is the authoritative record of the exact configure flags and compiler options
(`-matomics -mbulk-memory` among them) that shape the libraries. The native
script mirrors it; keeping the original makes that mirroring reviewable.

The Docker route still works if you want a fully reproducible Linux environment,
but it is not required -- see `WASM_BUILD_AND_RUN.md` sections 1.5 and 1.6.
