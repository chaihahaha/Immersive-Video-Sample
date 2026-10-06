#!/usr/bin/env python3
"""Static file server for the wasm player.

Cross-origin isolation is the point of this script: render.js is a pthreads
build, so it needs SharedArrayBuffer, and browsers only expose that when the
document is cross-origin isolated. COOP/COEP *must* arrive as real HTTP
response headers -- the <meta http-equiv=...> tags in the original index.html
are ignored for these two headers, which is one of the reasons the page could
never have worked when opened that way.

It can also serve the DASH content from a separate directory, which is what the
non-preloaded build needs (IVS_PRELOAD_CONTENT=OFF): the player then asks
local_curl for the MPD and each segment, and local_curl fetches them from
<contentBaseUrl> / ?contentBase=... over HTTP. Point --content at the directory
holding Gaslamp/ (tools/stage_content.sh produces it) and it is published as
/Gaslamp/....

Range requests are supported, because they are easy here and because someone
trying FS.createLazyFile (see WASM_BUILD_AND_RUN.md section 7) needs them;
Python's own SimpleHTTPRequestHandler does not implement them.

Usage:
    python3 tools/serve_wasm.py --root <build>/player/app [--content DIR] [--port 8000]
"""

import argparse
import functools
import http.server
import os
import re
import socketserver
import sys
import urllib.parse

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

# How much of a range to send in one go when the client asks for "everything
# from here on" (an open-ended range). Keeps a lazy reader from pulling a whole
# large file in a single response.
MAX_OPEN_RANGE = 8 * 1024 * 1024


class Handler(http.server.SimpleHTTPRequestHandler):
    # Set by main() to the directory published at --content-prefix.
    content_dir = None
    content_prefix = ""

    # ------------------------------------------------------------------ routing
    def translate_path(self, path):
        """Serve --content at the configured prefix, everything else from root."""
        if self.content_dir:
            decoded = urllib.parse.unquote(path.split("?", 1)[0].split("#", 1)[0])
            prefix = self.content_prefix
            if decoded == prefix or decoded.startswith(prefix + "/"):
                rest = decoded[len(prefix):].lstrip("/")
                # Reject traversal before joining.
                safe = os.path.normpath(os.path.join(self.content_dir, rest))
                if safe.startswith(self.content_dir):
                    return safe
        return super().translate_path(path)

    # ------------------------------------------------------------------ headers
    def end_headers(self):
        # Required for SharedArrayBuffer / WebAssembly threads.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        # Serve fresh assets while iterating on the build.
        self.send_header("Cache-Control", "no-store")
        # Advertise range support on every response, including HEAD, so a lazy
        # reader knows it may ask for chunks.
        self.send_header("Accept-Ranges", "bytes")
        super().end_headers()

    def guess_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in EXTRA_TYPES:
            return EXTRA_TYPES[ext]
        return super().guess_type(path)

    def log_message(self, fmt, *args):
        # Keep the console usable: only report non-2xx/3xx responses.
        status = args[1] if len(args) > 1 else ""
        text = str(status)
        if text.startswith("2") or text.startswith("3"):
            return
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -------------------------------------------------------------------- range
    def send_head(self):
        """SimpleHTTPRequestHandler.send_head() plus byte-range support.

        A Range request returns 206 with a Content-Range and a bounded body.
        Anything we cannot parse is ignored, which matches what a server is
        allowed to do and keeps the plain-GET path identical to before.
        """
        header = self.headers.get("Range")
        if not header:
            return super().send_head()

        match = re.match(r"^bytes=(\d*)-(\d*)$", header.strip())
        if not match:
            return super().send_head()
        first, last = match.group(1), match.group(2)
        if not first and not last:
            return super().send_head()

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            return super().send_head()
        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(404, "File not found")
            return None

        try:
            size = os.fstat(f.fileno()).st_size
            if first:
                start = int(first)
                end = int(last) if last else size - 1
            else:
                # Suffix range: the final N bytes.
                start = max(0, size - int(last))
                end = size - 1
            if start >= size or start > end:
                f.close()
                self.send_response(416)
                self.send_header("Content-Range", "bytes */%d" % size)
                self.end_headers()
                return None
            if end >= size:
                end = size - 1
            if not last and end - start + 1 > MAX_OPEN_RANGE:
                end = start + MAX_OPEN_RANGE - 1

            length = end - start + 1
            f.seek(start)
            self.send_response(206)
            self.send_header("Content-Type", self.guess_type(path))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
            self.send_header("Content-Length", str(length))
            self.end_headers()
            return _BoundedFile(f, length)
        except Exception:
            f.close()
            raise




class _BoundedFile:
    """Wraps a file object so copyfile() stops after `remaining` bytes."""

    def __init__(self, f, remaining):
        self.f = f
        self.remaining = remaining

    def read(self, n=-1):
        if self.remaining <= 0:
            return b""
        if n is None or n < 0 or n > self.remaining:
            n = self.remaining
        data = self.f.read(n)
        self.remaining -= len(data)
        return data

    def close(self):
        self.f.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="directory to serve")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument(
        "--content",
        default=None,
        help="staged DASH content, published at --content-prefix. Pass either the "
             "directory holding Gaslamp/ (e.g. webcontent) or Gaslamp/ itself. "
             "Needed only by the non-preloaded build.",
    )
    ap.add_argument("--content-prefix", default="/Gaslamp")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        sys.exit("not a directory: %s" % root)

    Handler.content_dir = None
    Handler.content_prefix = args.content_prefix.rstrip("/")
    if args.content:
        content = os.path.abspath(args.content)
        if not os.path.isdir(content):
            sys.exit("not a directory: %s" % content)
        # Accept either the directory that holds Gaslamp/ (tools/stage_content.sh
        # produces "webcontent/") or Gaslamp/ itself.
        nested = os.path.join(content, "Gaslamp")
        if os.path.isdir(nested):
            content = nested
        Handler.content_dir = content

    handler = functools.partial(Handler, directory=root)
    with Server((args.host, args.port), handler) as httpd:
        print("serving %s at http://%s:%d/" % (root, args.host, args.port))
        if Handler.content_dir:
            print("content %s at http://%s:%d%s/"
                  % (Handler.content_dir, args.host, args.port, Handler.content_prefix))
            print("  -> use ?contentBase=http://%s:%d%s" % (args.host, args.port, Handler.content_prefix))
        print("COOP: same-origin / COEP: require-corp, byte ranges supported")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
