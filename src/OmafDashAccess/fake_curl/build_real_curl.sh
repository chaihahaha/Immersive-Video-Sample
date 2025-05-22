#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.
set -u # Treat unset variables as an error.

# --- Configuration ---
CURL_VERSION="8.8.0" # Check for the latest version on curl.se
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/curl_build"
INSTALL_DIR="${SCRIPT_DIR}/curl_install_wasm"
NUM_JOBS=$(nproc || echo 1) # Number of parallel make jobs

# --- Ensure Emscripten is active ---
if ! command -v emcc &> /dev/null; then
    echo "Emscripten (emcc) not found in PATH. Please activate emsdk."
    exit 1
fi
echo "Using Emscripten: $(emcc --version)"

## --- Download and Extract libcurl ---
#if [ ! -f "curl-${CURL_VERSION}.tar.gz" ]; then
#    echo "Downloading curl-${CURL_VERSION}.tar.gz..."
#    wget -q "https://curl.se/download/curl-${CURL_VERSION}.tar.gz"
#fi

#echo "Extracting curl-${CURL_VERSION}.tar.bz2..."
#tar -xf "curl-${CURL_VERSION}.tar.bz2"

# --- Build ---
echo "Configuring and building libcurl for WASM..."
mkdir -p "${BUILD_DIR}"
cd "curl-${CURL_VERSION}"

# Critical: Use emconfigure to wrap ./configure
# Critical: --host=wasm32-emscripten to tell it we're cross-compiling for wasm
# Critical: --disable-shared --enable-static for a static library suitable for WASM
#
# Disabling features:
# --without-ssl          (umbrella for all SSL backends like OpenSSL, GnuTLS, mbedTLS etc.)
# --disable-crypto-auth  (disables various crypto authentication methods)
# --disable-manual       (don't build man pages)
# --disable-verbose      (reduce string constants for verbose mode)
# --disable-alt-svc      (HTTP Alternative Services, can be complex)
# --disable-cookies
# --disable-dateparse
# --disable-dnsshuffle
# --disable-doh          (DNS-over-HTTPS, requires HTTPS)
# --disable-ftp
# --disable-file
# --disable-gopher
# --disable-hsts
# --disable-http-auth    (disables most HTTP auth: Basic, Digest, NTLM, Negotiate)
# --disable-imap
# --disable-ldap
# --disable-ldaps
# --disable-mqtt
# --disable-netrc
# --disable-ntlm
# --disable-pop3
# --disable-progress-meter (can save some code if progress not needed)
# --disable-proxy
# --disable-pthreads     (Emscripten has pthreads, but simpler to disable if not strictly needed)
# --disable-rtsp
# --disable-smb
# --disable-smtp
# --disable-sspi
# --disable-telnet
# --disable-tftp
# --disable-threaded-resolver (use synchronous resolver)
# --disable-tls-srp
# --disable-unix-sockets
# --without-brotli
# --without-libidn2      (Internationalized Domain Names, can be complex)
# --without-libpsl       (Public Suffix List)
# --without-nghttp2      (HTTP/2)
# --without-ngtcp2       (HTTP/3 via ngtcp2)
# --without-nghttp3      (HTTP/3 via nghttp3)
# --without-zlib         (compression, can be added back if needed and zlib is compiled for wasm)
# --without-zstd
#
# Ensure HTTP is enabled, as it's the primary goal.
# --enable-http

# CFLAGS and LDFLAGS for Emscripten
# -s ASYNCIFY=1 is often needed for blocking C network calls to work in JS async environment
# -s ALLOW_MEMORY_GROWTH=1 is generally a good idea
# -O2 or -O3 for optimization
EM_CFLAGS="-O2 -sALLOW_MEMORY_GROWTH=1 -pthread -matomics -mbulk-memory"
EM_LDFLAGS="-sALLOW_MEMORY_GROWTH=1"

# Run emconfigure
echo "Running emconfigure..."
emconfigure ./configure \
    --host=wasm32-emscripten \
    --prefix="${INSTALL_DIR}" \
    --disable-shared \
    --enable-static \
    \
    --enable-http \
    \
    --without-ssl \
    --disable-crypto-auth \
    --disable-manual \
    --disable-verbose \
    --disable-alt-svc \
    --disable-cookies \
    --disable-dateparse \
    --disable-dnsshuffle \
    --disable-doh \
    --disable-ftp \
    --disable-file \
    --disable-gopher \
    --disable-hsts \
    --disable-http-auth \
    --disable-imap \
    --disable-ldap \
    --disable-ldaps \
    --disable-mqtt \
    --disable-netrc \
    --disable-ntlm \
    --disable-pop3 \
    --disable-progress-meter \
    --disable-proxy \
    --disable-rtsp \
    --disable-smb \
    --disable-smtp \
    --disable-sspi \
    --disable-telnet \
    --disable-tftp \
    --disable-threaded-resolver \
    --disable-tls-srp \
    --disable-unix-sockets \
    \
    --without-brotli \
    --without-libidn2 \
    --without-libpsl \
    --without-nghttp2 \
    --without-ngtcp2 \
    --without-nghttp3 \
    --without-zlib \
    --without-zstd \
    \
    CFLAGS="${EM_CFLAGS}" \
    LDFLAGS="${EM_LDFLAGS}" \
    PKG_CONFIG_PATH="${INSTALL_DIR}/lib/pkgconfig" # In case of dependencies, though we aim for none

# Run emmake
echo "Running emmake make..."
emmake make -j${NUM_JOBS}

echo "Running emmake make install..."
emmake make install

cd "${SCRIPT_DIR}"
echo "---------------------------------------------------------------------"
echo "Minimal libcurl build complete."
echo "Static library: ${INSTALL_DIR}/lib/libcurl.a"
echo "Include files:  ${INSTALL_DIR}/include/curl"
echo "---------------------------------------------------------------------"
echo "To use in your Emscripten project, link with:"
echo "  emcc your_code.c -I${INSTALL_DIR}/include ${INSTALL_DIR}/lib/libcurl.a -o output.html \\"
echo "       -s ASYNCIFY=1 -s ALLOW_MEMORY_GROWTH=1 \\"
echo "       -sEXPORTED_RUNTIME_METHODS='[\"ccall\", \"cwrap\"]' \\"
echo "       -sMODULARIZE=1 -sEXPORT_ES6=1 -sUSE_ES6_IMPORT_META=0 # (Example JS module flags)"
echo "---------------------------------------------------------------------"
echo "IMPORTANT: This build supports HTTP only. HTTPS will NOT work."
echo "           You MUST use -s ASYNCIFY=1 when linking your final application"
echo "           if you use libcurl's synchronous 'curl_easy_perform'."
echo "---------------------------------------------------------------------"
