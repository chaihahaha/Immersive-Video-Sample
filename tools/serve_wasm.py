#!/usr/bin/env python3
"""Static file server for the wasm player.

Cross-origin isolation is the point of this script: render.js is a pthreads
build, so it needs SharedArrayBuffer, and browsers only expose that when the
document is cross-origin isolated. COOP/COEP *must* arrive as real HTTP
response headers -- the <meta http-equiv=...> tags in the original index.html
are ignored for these two headers, which is one of the reasons the page could
never have worked when opened that way.

Usage:
    python3 tools/serve_wasm.py [--root DIR] [--port 8000]
"""

import argparse
import functools
import http.server
import os
import socketserver
import sys

EXTRA_TYPES = {
    ".wasm": "application/wasm",
    ".data": "application/octet-stream",
    ".map": "application/json",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".mp4": "video/mp4",
    ".m4s": "video/iso.segment",
    ".mpd": "application/dash+xml",
}


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Required for SharedArrayBuffer / WebAssembly threads.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        # Serve fresh assets while iterating on the build.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def guess_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in EXTRA_TYPES:
            return EXTRA_TYPES[ext]
        return super().guess_type(path)

    def log_message(self, fmt, *args):
        # Keep the console usable: only report non-200 responses.
        status = args[1] if len(args) > 1 else ""
        if str(status).startswith("2") or str(status) == "304":
            return
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="directory to serve")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.exit("not a directory: %s" % root)

    handler = functools.partial(Handler, directory=root)
    with Server((args.host, args.port), handler) as httpd:
        print("serving %s at http://%s:%d/" % (root, args.host, args.port))
        print("COOP: same-origin / COEP: require-corp")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
