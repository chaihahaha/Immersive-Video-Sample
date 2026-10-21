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

TLS (--tls) exists for one specific reason. Cross-origin isolation only works on
a "potentially trustworthy" origin, which means https, http://localhost or
http://127.0.0.1 -- *not* http://192.168.x.x. On a LAN address the browser
silently drops COOP/COEP ("The Cross-Origin-Opener-Policy header has been
ignored, because the URL's origin was untrustworthy"), crossOriginIsolated stays
false, and the pthreads build dies with "SharedArrayBuffer is not defined".
Serving over https fixes that; --tls generates (and caches) a certificate whose
SANs cover every local IPv4 address.

Usage:
    python3 tools/serve_wasm.py --root <build>/player/app [--content DIR] [--port 8000]
    python3 tools/serve_wasm.py --root <build>/player/app --host 0.0.0.0 --port 9999 --tls
"""

import argparse
import errno
import functools
import http.server
import ipaddress
import os
import re
import socket
import socketserver
import ssl
import subprocess
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
    # Set by main() when --tls is used. The handshake is done per connection
    # inside its own thread, never in accept(); see get_request().
    tls_context = None
    handshake_timeout = 20.0

    def handle_error(self, request, client_address):
        """A browser aborting a 40 MB wasm download is normal, not a bug."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)

    def get_request(self):
        """accept() only. Never wrap the listening socket in TLS.

        Wrapping it means the handshake happens inside accept(), which runs on
        the single serve_forever() thread. Browsers open speculative
        connections and leave them silent for a while, so one idle socket would
        freeze every other request until it timed out -- which is exactly the
        "render.wasm / render.data: ERR_CONNECTION_RESET" the client saw, while
        index.html and render.js (small, requested first) worked.
        """
        sock, addr = self.socket.accept()
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            raw = request
            try:
                request.settimeout(self.handshake_timeout)
                request = self.tls_context.wrap_socket(raw, server_side=True)
                # Back to a blocking socket: a timeout in the middle of a 50 MB
                # write would abort the transfer.
                request.settimeout(None)
            except (ssl.SSLError, OSError):
                self.shutdown_request(raw)
                return
        super().process_request_thread(request, client_address)


# --------------------------------------------------------------------- TLS bits
#
# Why a certificate at all: see the module docstring. The awkward part is that
# no public CA will vouch for 192.168.x.x, so trust has to be established by
# hand on each client. Two ways to do that, both supported here:
#
#   mkcert  -- reuse the local dev CA. Already trusted on this machine; other
#              machines need rootCA.pem installed once (it is printed below).
#   self    -- throwaway self-signed cert. Browsers show "Not secure" and need a
#              click-through, but the origin still becomes a secure context, so
#              SharedArrayBuffer works. Zero setup on the server side.

CERT_DIR_NAME = ".wasm-dev-cert"


def _run(cmd):
    """Run a command, returning stdout, or None if it is not usable."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def _local_ipv4(timeout=1.0):
    """Best-effort list of this host's non-loopback IPv4 addresses."""
    ips = set()
    # 1. Whatever the hostname resolves to (usually right on macOS). Deliberately
    #    no "<host>.local" lookup here: that goes through mDNS and can block for
    #    seconds. The name is still put in the certificate, just not resolved.
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    # 2. The address of the default route. A UDP connect() sends no packet but
    #    does make the kernel pick a source address.
    for probe in ("192.0.2.1", "8.8.8.8"):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.connect((probe, 53))
            ips.add(s.getsockname()[0])
            break
        except OSError:
            continue
        finally:
            if s is not None:
                s.close()
    # 3. Interface enumeration, for the secondary interfaces the route lookup
    #    above cannot see. Both tools are tried; either may be missing.
    for argv in (["ifconfig"], ["ip", "-4", "-o", "addr"]):
        text = _run(argv)
        if text:
            for ip in re.findall(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", text):
                ips.add(ip)
            break
    return sorted(ip for ip in ips
                  if not ip.startswith("127.") and not ip.startswith("169.254."))


def _cert_names(extra):
    """Names/IPs the certificate must cover."""
    names = ["localhost", "127.0.0.1", "::1"]
    try:
        host = socket.gethostname()
        if host and host != "localhost":
            names.append(host)
            if "." not in host:
                names.append(host + ".local")
    except OSError:
        pass
    names.extend(_local_ipv4())
    for item in extra or ():
        names.extend(part.strip() for part in item.split(",") if part.strip())
    seen, ordered = set(), []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def _cert_covers(cert_path, names):
    """True when an existing certificate already has SANs for every name."""
    text = _run(["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"])
    if not text:
        return False
    dns, ips = set(), set()
    for kind, value in re.findall(r"(DNS|IP Address):([^,\s]+)", text):
        if kind == "DNS":
            dns.add(value.lower())
        else:
            try:
                ips.add(ipaddress.ip_address(value))
            except ValueError:
                pass
    for name in names:
        try:
            if ipaddress.ip_address(name) not in ips:
                return False
        except ValueError:
            if name.lower() not in dns:
                return False
    return True


def _who_listens(port):
    """Best-effort "pid command" of the process holding a TCP port."""
    out = _run(["lsof", "-nP", "-tiTCP:%d" % port, "-sTCP:LISTEN"])
    if not out:
        return None
    pid = out.split()[0]
    cmd = _run(["ps", "-p", pid, "-o", "command="])
    return "%s (%s)" % (pid, (cmd or "").strip()[:90]) if cmd else pid


def _mkcert_ca():
    """Path to mkcert's root CA, if mkcert is installed and initialised."""
    out = _run(["mkcert", "-CAROOT"])
    if not out:
        return None
    ca = os.path.join(out.strip(), "rootCA.pem")
    return ca if os.path.isfile(ca) else None


def _is_mkcert_signed(cert_path):
    text = _run(["openssl", "x509", "-in", cert_path, "-noout", "-issuer", "-subject"])
    if not text:
        return False
    issuer = next((line for line in text.splitlines() if line.startswith("issuer=")), "")
    subject = next((line for line in text.splitlines() if line.startswith("subject=")), "")
    return "mkcert" in issuer and issuer != subject


def _make_cert(cert_path, key_path, names, mode):
    """Create cert_path/key_path. Returns (ok, how) where how is for printing."""
    if mode in ("auto", "mkcert"):
        ca = _mkcert_ca()
        if ca:
            # mkcert regenerates on every call, and needs no password because
            # the CA already exists.
            out = _run(["mkcert",
                        "-cert-file", cert_path,
                        "-key-file", key_path] + names)
            if out is not None and os.path.isfile(cert_path):
                return True, "mkcert"
            if mode == "mkcert":
                return False, "mkcert"
    if mode == "mkcert":
        return False, "mkcert"

    sans = ",".join(
        ("IP:%s" % name) if re.match(r"^[0-9.]+$|^[0-9a-f:]+$", name) else ("DNS:%s" % name)
        for name in names
    )
    out = _run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
        "-days", "825",
        "-keyout", key_path, "-out", cert_path,
        "-subj", "/CN=ivs-wasm-dev",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectAltName=" + sans,
    ])
    if out is None or not os.path.isfile(cert_path):
        return False, "self"
    return True, "self"


def _ensure_cert(cert_dir, names, mode):
    """Return (cert, key, how), generating or refreshing as needed."""
    os.makedirs(cert_dir, exist_ok=True)
    cert = os.path.join(cert_dir, "cert.pem")
    key = os.path.join(cert_dir, "key.pem")
    if os.path.isfile(cert) and os.path.isfile(key) and _cert_covers(cert, names):
        return cert, key, "cache"
    ok, how = _make_cert(cert, key, names, mode)
    if not ok:
        sys.exit("could not create a TLS certificate (is openssl or mkcert on PATH?)")
    return cert, key, how


def _scheme(args):
    return "https" if args.tls else "http"


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
    ap.add_argument("--tls", action="store_true",
                    help="serve https; required for cross-origin isolation when the "
                         "page is opened from another machine over a LAN IP")
    ap.add_argument("--tls-cert", default=None, help="use this certificate instead")
    ap.add_argument("--tls-key", default=None, help="use this private key instead")
    ap.add_argument("--tls-san", action="append", default=None,
                    help="extra DNS name or IP to put in the generated certificate "
                         "(repeatable, or comma separated)")
    ap.add_argument("--tls-ca", choices=("auto", "mkcert", "self"), default="auto",
                    help="who signs the generated certificate: mkcert's local dev CA "
                         "when available, else a throwaway self-signed one")
    ap.add_argument("--tls-dir", default=None,
                    help="where to cache the generated certificate "
                         "(default: ./%s in the current directory)" % CERT_DIR_NAME)
    args = ap.parse_args()

    if (args.tls_cert is None) != (args.tls_key is None):
        sys.exit("--tls-cert and --tls-key go together")
    if args.tls_cert:
        args.tls = True

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

    cert = key = how = None
    if args.tls:
        if args.tls_cert:
            cert, key, how = args.tls_cert, args.tls_key, "given"
        else:
            names = _cert_names(args.tls_san)
            cert_dir = os.path.abspath(args.tls_dir or
                                       os.path.join(os.getcwd(), CERT_DIR_NAME))
            cert, key, how = _ensure_cert(cert_dir, names, args.tls_ca)

    handler = functools.partial(Handler, directory=root)
    scheme = _scheme(args)
    try:
        httpd = Server((args.host, args.port), handler)
    except OSError as exc:
        if exc.errno != errno.EADDRINUSE:
            raise
        # The classic footgun: an older server is still holding the port, so the
        # browser keeps talking to *it*, and none of the new flags take effect.
        holder = _who_listens(args.port)
        lines = ["port %d is already in use%s" % (args.port, " by " + holder if holder else "")]
        lines.append("  A server started earlier is still running, so the browser is")
        lines.append("  talking to that one -- not to this one. Restart it before the")
        lines.append("  browser will see any change:")
        if holder:
            lines.append("    kill %s" % holder.split()[0])
        else:
            lines.append("    lsof -nP -iTCP:%d -sTCP:LISTEN" % args.port)
        sys.exit("\n".join(lines))
    with httpd:
        if args.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            httpd.tls_context = ctx
        print("serving %s at %s://%s:%d/" % (root, scheme, args.host, args.port))
        if Handler.content_dir:
            print("content %s at %s://%s:%d%s/"
                  % (Handler.content_dir, scheme, args.host, args.port,
                     Handler.content_prefix))
            print("  -> use ?contentBase=%s://%s:%d%s"
                  % (scheme, args.host, args.port, Handler.content_prefix))
        print("COOP: same-origin / COEP: require-corp, byte ranges supported")
        if args.tls:
            print("TLS: %s (certificate %s)" % (how, cert))
            for host in ["127.0.0.1"] + _local_ipv4():
                print("  %s://%s:%d/" % (scheme, host, args.port))
            if _is_mkcert_signed(cert):
                ca = _mkcert_ca()
                print("  signed by mkcert's local CA, which is trusted here.")
                print("  other machines must trust it first -- copy %s and import it:"
                      % ca)
                print("    macOS:   sudo security add-trusted-cert -d -r trustRoot "
                      "-k /Library/Keychains/System.keychain rootCA.pem")
                print("    Linux:   sudo cp rootCA.pem /usr/local/share/ca-certificates/"
                      "mkcert.crt && sudo update-ca-certificates")
                print("    Windows: certutil -addstore -f Root rootCA.pem")
            elif how == "given":
                print("  using the certificate passed on the command line.")
            else:
                print("  self-signed: browsers will warn -- click through, the origin")
                print("  still counts as secure, so SharedArrayBuffer becomes available.")
        elif args.host not in ("127.0.0.1", "localhost", "::1"):
            print("NOTE: %s://%s:%d/ is not a secure origin, so COOP/COEP are ignored"
                  % (scheme, args.host, args.port))
            print("      and the page will fail with 'SharedArrayBuffer is not defined'.")
            print("      Add --tls to serve https (see WASM_BUILD_AND_RUN.md section 4).")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
