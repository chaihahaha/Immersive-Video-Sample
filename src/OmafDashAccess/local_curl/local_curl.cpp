/*
 * local_curl.cpp
 *
 * A synchronous, local-filesystem-backed implementation of the small libcurl
 * subset that OmafDashAccess actually uses.
 *
 * WHY THIS EXISTS
 * ---------------
 * The real libcurl does compile and link for wasm32-emscripten (see
 * fake_curl/build_real_curl.sh, which produced ffmpeg_wasm_lib/lib/libcurl.a),
 * but it can never transfer anything in the browser: its socket layer resolves
 * to Emscripten's POSIX socket emulation, which only works when the app is
 * linked with -sPROXY_POSIX_SOCKETS *and* an external WebSocket-to-POSIX proxy
 * server is running. The previous build's wasm import table confirms this --
 * there is no socket/connect/getaddrinfo import at all, only select, so the
 * transfer layer is simply absent (this is the bug recorded in commit 189987d,
 * "this fails because of web socket proxying bug").
 *
 * Meanwhile every byte of the Gaslamp package (Test.mpd plus 14448 segment
 * files) is already inside the Emscripten virtual filesystem via
 * --preload-file. There is nothing to download. So instead of pretending to be
 * a network stack, this file implements curl synchronously on top of
 * fopen()/fread().
 *
 * Because it is synchronous and single-threaded, it matches real libcurl's
 * contract exactly where the emscripten_fetch shim (fake_curl/) could not:
 *   - curl_multi_perform() actually performs the transfers and makes progress;
 *   - curl_multi_info_read() returns CURLMSG_DONE with a meaningful result;
 *   - curl_easy_getinfo() returns real values rather than -1 or uninitialised
 *     stack memory.
 *
 * URL -> PATH MAPPING
 * -------------------
 * The OMAF stack builds segment URLs from the MPD BaseURL (here "/VOD8K/") plus
 * the SegmentTemplate media name, and hands them straight to this layer. The
 * files however live in the preloaded directory given by <cachePath> in
 * config.xml, and their names are flat. Resolution therefore tries, in order:
 *   1. the path component of the URL as an absolute VFS path;
 *   2. <root>/<basename>     <- this is the one that normally hits
 *   3. <root>/<path>;
 *   4. <basename> relative to the current directory.
 * <root> is set once at startup from RenderConfig::cachePath via
 * em_local_curl_set_root().
 */

#include <curl/curl.h>

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define LOCAL_CURL_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define LOCAL_CURL_EXPORT
#endif

namespace {

std::string g_root;

// ---------------------------------------------------------------------------
// Bandwidth pacing.
//
// Reading from the virtual filesystem is a memcpy, so without pacing the OMAF
// reader thread downloads the entire presentation in seconds -- far faster than
// the wasm decoder can consume it -- and the backlog exhausts the WebAssembly
// heap. A token bucket caps the aggregate delivery rate so the reader stays
// roughly in step with playback. 0 disables the limit.
// ---------------------------------------------------------------------------
// Diagnostics: how many transfers ran and how many bytes they delivered.
// Read from the page via Module.ccall('em_local_curl_transfer_count', ...).
unsigned long g_transfer_count = 0;
unsigned long g_bytes_delivered = 0;

std::mutex g_rate_mutex;
double g_rate_limit = 0.0;  // bytes per second
double g_tokens = 0.0;
std::chrono::steady_clock::time_point g_last_refill;

void pace_bytes(size_t bytes) {
  if (g_rate_limit <= 0.0) return;

  std::unique_lock<std::mutex> lock(g_rate_mutex);
  const auto now = std::chrono::steady_clock::now();
  if (g_last_refill.time_since_epoch().count() == 0) {
    g_last_refill = now;
    g_tokens = g_rate_limit * 0.25;  // small initial burst
  }
  const double dt = std::chrono::duration<double>(now - g_last_refill).count();
  g_last_refill = now;

  g_tokens += dt * g_rate_limit;
  const double burst = g_rate_limit * 0.25;  // never accumulate more than 250 ms
  if (g_tokens > burst) g_tokens = burst;

  g_tokens -= static_cast<double>(bytes);

  double wait_seconds = 0.0;
  if (g_tokens < 0.0) {
    wait_seconds = -g_tokens / g_rate_limit;
    g_tokens = 0.0;
  }
  lock.unlock();

  if (wait_seconds > 0.0) {
    usleep(static_cast<useconds_t>(wait_seconds * 1e6));
  }
}

std::string basename_of(const std::string &p) {
  size_t s = p.find_last_of('/');
  return (s == std::string::npos) ? p : p.substr(s + 1);
}

std::string path_part_of(const std::string &url) {
  std::string s = url;
  size_t scheme = s.find("://");
  if (scheme != std::string::npos) {
    size_t slash = s.find('/', scheme + 3);
    s = (slash == std::string::npos) ? std::string() : s.substr(slash);
  }
  size_t q = s.find_first_of("?#");
  if (q != std::string::npos) s = s.substr(0, q);
  return s;
}

void candidate_paths(const std::string &url, std::vector<std::string> *out) {
  std::string p = path_part_of(url);
  std::string base = basename_of(p);

  if (!p.empty()) out->push_back(p);
  if (!g_root.empty() && !base.empty()) out->push_back(g_root + "/" + base);
  if (!g_root.empty() && !p.empty()) {
    out->push_back(g_root + "/" + (p[0] == '/' ? p.substr(1) : p));
  }
  if (!base.empty()) out->push_back(base);
}

// ---------------------------------------------------------------------------
// Optional HTTP backend.
//
// When a base URL is configured (config.xml <contentBaseUrl>), any resource that
// is NOT already in the virtual filesystem is fetched over HTTP. That lets the
// Gaslamp package be served by an ordinary web server instead of being baked
// into render.data by --preload-file.
//
// What that saves is the browser's JS heap, not wasm memory: file_packager backs
// MEMFS with a JS Uint8Array built from the XHR response, whereas this backend
// wraps each response in an fmemopen() stream that is released as soon as the
// transfer finishes. Measured with the preload build replaced by this one:
// /Gaslamp holds 57 MB of MEMFS content vs 0.1 MB (just the MPD), while
// em_probe_live_kb and HEAPU8.length are unchanged.
//
// The fetch is a *synchronous* XMLHttpRequest. That sounds impossible in a
// browser, but it is not: synchronous XHR is only forbidden on the main thread,
// and every caller of this file runs on an Emscripten pthread, which is a real
// Web Worker. Emscripten's own FS.createLazyFile is built on the same trick and
// says so in its source ("Lazy loading only works in web workers").
//
// Staying synchronous is the whole point: OmafDashAccess expects
// curl_easy_perform()/curl_multi_perform() to have completed the transfer by the
// time they return, so no call site has to change. Only small files are ever
// fetched this way -- the MPD (113 KB) and one segment at a time (10-30 KB) --
// so pulling the whole body in a single request is fine and HTTP Range support
// is not needed.
// ---------------------------------------------------------------------------
std::string g_http_base;

unsigned long g_http_fetches = 0;
unsigned long g_http_bytes = 0;
unsigned long g_http_failures = 0;
int g_http_last_status = 0;

#ifdef __EMSCRIPTEN__
// Returns a malloc'd buffer holding the whole response body, or nullptr.
// *out_len receives the byte count; *out_status receives the HTTP status, or -1
// if the request itself failed. Ownership passes to the caller (free() it).
EM_JS(void *, ivs_http_get_sync, (const char *url, int *out_len, int *out_status), {
  setValue(out_len, 0, 'i32');
  setValue(out_status, 0, 'i32');
  try {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', UTF8ToString(url), false);   // false => synchronous
    xhr.responseType = 'arraybuffer';
    xhr.send();
    setValue(out_status, xhr.status, 'i32');
    if (xhr.status < 200 || xhr.status >= 300) return 0;
    var bytes = new Uint8Array(xhr.response);
    var ptr = _malloc(bytes.length ? bytes.length : 1);
    if (!ptr) return 0;
    HEAPU8.set(bytes, ptr);
    setValue(out_len, bytes.length, 'i32');
    return ptr;
  } catch (err) {
    setValue(out_status, -1, 'i32');
    return 0;
  }
});
#endif

// fmemopen() streams read from a buffer that the caller still owns, so the
// buffer has to outlive the FILE*. Track it here and release it in close_file().
std::mutex g_mem_stream_mutex;
std::unordered_map<FILE *, void *> g_mem_streams;

FILE *open_memory(void *data, size_t len) {
  if (!data) return nullptr;
  FILE *f = fmemopen(data, len, "rb");
  if (!f) {
    free(data);
    return nullptr;
  }
  {
    std::lock_guard<std::mutex> lock(g_mem_stream_mutex);
    g_mem_streams[f] = data;
  }
  return f;
}

// The single close path for both virtual-filesystem files and memory streams.
// Safe to call on a plain VFS FILE*.
void close_file(FILE *f) {
  if (!f) return;
  void *owned = nullptr;
  {
    std::lock_guard<std::mutex> lock(g_mem_stream_mutex);
    auto it = g_mem_streams.find(f);
    if (it != g_mem_streams.end()) {
      owned = it->second;
      g_mem_streams.erase(it);
    }
  }
  fclose(f);
  free(owned);  // never reachable for VFS files: owned stays nullptr
}

void http_candidates(const std::string &url, std::vector<std::string> *out) {
  if (g_http_base.empty()) return;
  const std::string p = path_part_of(url);
  const std::string base = basename_of(p);
  // The staged content directory is flat, so <base>/<basename> is the one that
  // normally hits. The second form mirrors the URL's own path underneath the
  // base, for a server that keeps the DASH directory structure.
  if (!base.empty()) out->push_back(g_http_base + "/" + base);
  if (!p.empty()) out->push_back(g_http_base + "/" + (p[0] == '/' ? p.substr(1) : p));
}

// Downloads one of the HTTP candidates for `url`. On success returns the
// malloc'd body and stores its size in *out_len; the caller owns the buffer.
void *http_fetch(const std::string &url, int *out_len) {
  *out_len = 0;
#ifdef __EMSCRIPTEN__
  std::vector<std::string> candidates;
  http_candidates(url, &candidates);
  if (candidates.empty()) return nullptr;

  for (const std::string &c : candidates) {
    int len = 0;
    int status = 0;
    void *data = ivs_http_get_sync(c.c_str(), &len, &status);
    g_http_last_status = status;
    if (!data) continue;
    g_http_fetches++;
    g_http_bytes += static_cast<unsigned long>(len);
    *out_len = len;
    return data;
  }
  g_http_failures++;
#else
  (void)url;
#endif
  return nullptr;
}

FILE *open_over_http(const std::string &url) {
  int len = 0;
  void *data = http_fetch(url, &len);
  if (!data) return nullptr;
  return open_memory(data, static_cast<size_t>(len));
}

// Fetches `url` over HTTP and writes it into the virtual filesystem.
//
// Needed because not every reader goes through this curl shim: the MPD in
// particular is loaded by OmafXMLParser with tinyxml2's XMLDocument::LoadFile(),
// i.e. a plain file read. Materialising it in the VFS first makes that work
// unchanged.
//
// The transfer is run on a helper thread on purpose. A synchronous
// XMLHttpRequest may only set responseType = 'arraybuffer' from a worker -- a
// document thread throws InvalidAccessError -- and this is called from main().
// An Emscripten pthread is a real Web Worker, so the request happens there while
// the caller still gets a synchronous answer.
int prefetch_impl(const std::string &url) {
  std::vector<std::string> candidates;
  candidate_paths(url, &candidates);
  if (candidates.empty()) return -1;

  // Already present (preloaded, or a previous prefetch): nothing to do.
  for (const std::string &c : candidates) {
    FILE *f = fopen(c.c_str(), "rb");
    if (f) {
      fclose(f);
      return 0;
    }
  }
  if (g_http_base.empty()) return -1;

  int len = 0;
  void *data = http_fetch(url, &len);
  if (!data) return -1;

  // The parent directory may not exist in the virtual filesystem yet.
  const std::string &dest = candidates[0];
  const size_t slash = dest.find_last_of('/');
  if (slash != std::string::npos && slash > 0) {
    mkdir(dest.substr(0, slash).c_str(), 0777);  // ignore EEXIST
  }

  FILE *out = fopen(dest.c_str(), "wb");
  if (!out) {
    free(data);
    return -1;
  }
  const size_t written = fwrite(data, 1, static_cast<size_t>(len), out);
  fclose(out);
  free(data);
  return written == static_cast<size_t>(len) ? 0 : -1;
}

// url -> resolved VFS path. Every segment is requested repeatedly, and the
// original implementation probed up to four candidates with fopen()/fclose()
// on every single transfer, which is a lot of stdio churn for no benefit.
std::mutex g_path_cache_mutex;
std::unordered_map<std::string, std::string> g_path_cache;

FILE *open_resolved(const std::string &url, std::string *path_out) {
  {
    std::lock_guard<std::mutex> lock(g_path_cache_mutex);
    auto it = g_path_cache.find(url);
    if (it != g_path_cache.end()) {
      FILE *f = fopen(it->second.c_str(), "rb");
      if (f) {
        *path_out = it->second;
        return f;
      }
      g_path_cache.erase(it);  // stale entry, re-resolve below
    }
  }

  std::vector<std::string> candidates;
  candidate_paths(url, &candidates);
  for (const std::string &c : candidates) {
    FILE *f = fopen(c.c_str(), "rb");
    if (f) {
      {
        std::lock_guard<std::mutex> lock(g_path_cache_mutex);
        g_path_cache[url] = c;
      }
      *path_out = c;
      return f;
    }
  }
  // Not in the virtual filesystem: fall back to HTTP when a base URL is set.
  // Deliberately not recorded in g_path_cache, which maps a URL to a VFS path
  // that can be reopened later with fopen(); a fetched body is not that.
  if (!g_http_base.empty()) {
    FILE *f = open_over_http(url);
    if (f) {
      *path_out = url;
      return f;
    }
  }

  *path_out = candidates.empty() ? std::string() : candidates[0];
  return nullptr;
}

struct EasyHandle {
  // request
  std::string url;
  std::string range;  // raw CURLOPT_RANGE value: "0-1023", "1024-", "-512"
  bool nobody = false;
  long timeout_ms = 0;
  long connecttimeout_ms = 0;
  curl_write_callback write_fn = nullptr;
  void *write_data = nullptr;
  std::string private_copy;
  char *error_buffer = nullptr;

  // response
  CURLcode result = CURLE_OK;
  long response_code = 0;
  curl_off_t content_length_download = -1;
  curl_off_t size_download = 0;
  curl_off_t speed_download = 0;
  curl_off_t total_time = 0;
  curl_off_t namelookup_time = 0;
  curl_off_t connect_time = 0;
  curl_off_t appconnect_time = 0;
  curl_off_t pretransfer_time = 0;
  curl_off_t starttransfer_time = 0;
  curl_off_t redirect_time = 0;

  // multi bookkeeping
  bool in_multi = false;
  bool completed = false;
};

struct MultiHandle {
  long maxconnects = 0;
  std::list<EasyHandle *> handles;
  std::list<CURLMsg> messages;
  CURLMsg last_message;  // storage for the pointer returned by info_read
};

inline EasyHandle *as_easy(CURL *h) { return reinterpret_cast<EasyHandle *>(h); }
inline MultiHandle *as_multi(CURLM *h) { return reinterpret_cast<MultiHandle *>(h); }

void set_error(EasyHandle *e, CURLcode code, const char *msg) {
  e->result = code;
  if (e->error_buffer && msg) {
    strncpy(e->error_buffer, msg, CURL_ERROR_SIZE - 1);
    e->error_buffer[CURL_ERROR_SIZE - 1] = '\0';
  }
  fprintf(stderr, "[local_curl] error %d: %s\n", static_cast<int>(code), msg ? msg : "");
}

bool parse_range(const std::string &r, curl_off_t total, curl_off_t *start, curl_off_t *len) {
  size_t dash = r.find('-');
  if (dash == std::string::npos) return false;
  std::string a = r.substr(0, dash);
  std::string b = r.substr(dash + 1);

  if (a.empty()) {  // "-N": last N bytes
    if (b.empty()) return false;
    curl_off_t n = static_cast<curl_off_t>(strtoll(b.c_str(), nullptr, 10));
    if (n <= 0) return false;
    if (n > total) n = total;
    *start = total - n;
    *len = n;
    return true;
  }

  curl_off_t s = static_cast<curl_off_t>(strtoll(a.c_str(), nullptr, 10));
  if (s < 0) return false;
  if (s >= total) {
    *start = total;
    *len = 0;
    return true;
  }
  curl_off_t e = total - 1;
  if (!b.empty()) {
    curl_off_t be = static_cast<curl_off_t>(strtoll(b.c_str(), nullptr, 10));
    if (be >= 0 && be < e) e = be;
  }
  *start = s;
  *len = e - s + 1;
  return true;
}

CURLcode perform_transfer(EasyHandle *e) {
  e->result = CURLE_OK;
  e->response_code = 0;
  e->content_length_download = -1;
  e->size_download = 0;
  e->speed_download = 0;

  if (e->url.empty()) {
    set_error(e, CURLE_URL_MALFORMAT, "no URL set");
    return e->result;
  }

  std::string path;
  FILE *f = open_resolved(e->url, &path);
  if (!f) {
    std::string msg = "cannot open '" + path + "' for URL '" + e->url + "'";
    if (!g_http_base.empty()) {
      msg += " and HTTP fetch from base '" + g_http_base + "' failed";
      if (g_http_last_status == -1) {
        msg += " (request error)";
      } else if (g_http_last_status != 0) {
        msg += " (HTTP " + std::to_string(g_http_last_status) + ")";
      }
    }
    set_error(e, CURLE_FILE_COULDNT_READ_FILE, msg.c_str());
    return e->result;
  }

  if (fseek(f, 0, SEEK_END) != 0) {
    close_file(f);
    set_error(e, CURLE_FILE_COULDNT_READ_FILE, "seek to end failed");
    return e->result;
  }
  curl_off_t total = static_cast<curl_off_t>(ftell(f));
  if (total < 0) total = 0;

  curl_off_t start = 0;
  curl_off_t len = total;

  if (!e->range.empty()) {
    if (!parse_range(e->range, total, &start, &len)) {
      close_file(f);
      set_error(e, CURLE_RANGE_ERROR, "invalid CURLOPT_RANGE value");
      return e->result;
    }
    e->response_code = 206;
  } else {
    e->response_code = 200;
  }

  if (e->nobody) {
    // HEAD: no body, but Content-Length still describes the resource.
    e->content_length_download = total;
    close_file(f);
    g_transfer_count++;
    return e->result;
  }

  e->content_length_download = len;

  if (fseek(f, static_cast<long>(start), SEEK_SET) != 0) {
    close_file(f);
    set_error(e, CURLE_FILE_COULDNT_READ_FILE, "seek to range start failed");
    return e->result;
  }

  const size_t kChunk = 256 * 1024;
  std::vector<char> buf(kChunk);
  curl_off_t remaining = len;
  while (remaining > 0) {
    size_t want = static_cast<size_t>(std::min<curl_off_t>(remaining, static_cast<curl_off_t>(kChunk)));
    size_t got = fread(buf.data(), 1, want, f);
    if (got == 0) break;
    if (e->write_fn) {
      size_t written = e->write_fn(buf.data(), 1, got, e->write_data);
      if (written < got) {
        close_file(f);
        set_error(e, CURLE_WRITE_ERROR, "write callback accepted fewer bytes than supplied");
        return e->result;
      }
    }
    remaining -= static_cast<curl_off_t>(got);
    e->size_download += static_cast<curl_off_t>(got);
    g_bytes_delivered += static_cast<unsigned long>(got);
    pace_bytes(got);
  }
  close_file(f);
  g_transfer_count++;

  if (remaining > 0) {
    set_error(e, CURLE_PARTIAL_FILE, "short read from local resource");
  }
  return e->result;
}

}  // namespace

// Lets the player declare where the preloaded content lives
// (RenderConfig::cachePath). Not part of the curl API.
extern "C" void em_local_curl_set_root(const char *root) {
  g_root = (root && root[0]) ? std::string(root) : std::string();
  while (g_root.size() > 1 && g_root.back() == '/') g_root.pop_back();
  fprintf(stderr, "[local_curl] content root = '%s'\n", g_root.c_str());
}

// Enables the HTTP backend: resources that are not in the virtual filesystem
// are fetched from this base URL (RenderConfig::contentBaseUrl). An empty string
// keeps the player purely filesystem-backed.
extern "C" void em_local_curl_set_http_base(const char *base) {
  g_http_base = (base && base[0]) ? std::string(base) : std::string();
  while (g_http_base.size() > 1 && g_http_base.back() == '/') g_http_base.pop_back();
  if (!g_http_base.empty()) {
    fprintf(stderr, "[local_curl] HTTP content base = '%s'\n", g_http_base.c_str());
  }
}

// Materialises an HTTP resource in the virtual filesystem so readers that use
// plain file I/O -- the MPD parser in particular -- can find it. Returns 0 when
// the file is available afterwards (already present, or downloaded).
extern "C" int em_local_curl_prefetch(const char *url) {
  if (!url || !url[0]) return -1;
  const std::string target(url);
  int rc = -1;
  // See prefetch_impl: the XHR has to happen on a worker thread.
  std::thread helper([&rc, &target]() { rc = prefetch_impl(target); });
  helper.join();
  if (rc != 0) {
    fprintf(stderr, "[local_curl] prefetch failed for '%s'\n", url);
  }
  return rc;
}

extern "C" LOCAL_CURL_EXPORT unsigned long em_local_curl_http_fetches(void) {
  return g_http_fetches;
}

extern "C" LOCAL_CURL_EXPORT unsigned long em_local_curl_http_bytes(void) {
  return g_http_bytes;
}

extern "C" LOCAL_CURL_EXPORT unsigned long em_local_curl_http_failures(void) {
  return g_http_failures;
}

// Caps the aggregate delivery rate (bytes/second). 0 means "as fast as the
// filesystem allows", which is what caused the reader thread to race hundreds
// of segments ahead of the renderer and exhaust the wasm heap.
extern "C" LOCAL_CURL_EXPORT unsigned long em_local_curl_transfer_count(void) {
  return g_transfer_count;
}

extern "C" LOCAL_CURL_EXPORT unsigned long em_local_curl_bytes_delivered(void) {
  return g_bytes_delivered;
}

extern "C" void em_local_curl_set_rate_limit(double bytes_per_second) {
  std::lock_guard<std::mutex> lock(g_rate_mutex);
  g_rate_limit = (bytes_per_second > 0.0) ? bytes_per_second : 0.0;
  g_tokens = 0.0;
  g_last_refill = std::chrono::steady_clock::time_point();
  fprintf(stderr, "[local_curl] rate limit = %.0f bytes/s\n", g_rate_limit);
}

// ---------------------------------------------------------------------------
// Global
// ---------------------------------------------------------------------------

extern "C" CURLcode curl_global_init(long flags) {
  (void)flags;
  return CURLE_OK;
}

extern "C" void curl_global_cleanup(void) {}

// ---------------------------------------------------------------------------
// Easy interface
// ---------------------------------------------------------------------------

extern "C" CURL *curl_easy_init(void) { return reinterpret_cast<CURL *>(new (std::nothrow) EasyHandle()); }

extern "C" void curl_easy_reset(CURL *handle) {
  EasyHandle *e = as_easy(handle);
  if (!e) return;
  char *err = e->error_buffer;
  *e = EasyHandle();
  e->error_buffer = err;
}

extern "C" CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...) {
  EasyHandle *e = as_easy(handle);
  if (!e) return CURLE_BAD_FUNCTION_ARGUMENT;

  va_list arg;
  va_start(arg, option);
  CURLcode rc = CURLE_OK;

  switch (option) {
    case CURLOPT_URL: {
      const char *p = va_arg(arg, const char *);
      e->url = p ? p : "";
      break;
    }
    case CURLOPT_RANGE: {
      const char *p = va_arg(arg, const char *);
      e->range = p ? p : "";
      break;
    }
    case CURLOPT_NOBODY:
      e->nobody = (va_arg(arg, long) != 0);
      break;
    case CURLOPT_TIMEOUT_MS:
      e->timeout_ms = va_arg(arg, long);
      break;
    case CURLOPT_CONNECTTIMEOUT_MS:
      e->connecttimeout_ms = va_arg(arg, long);
      break;
    case CURLOPT_WRITEFUNCTION:
      e->write_fn = va_arg(arg, curl_write_callback);
      break;
    case CURLOPT_WRITEDATA:
      e->write_data = va_arg(arg, void *);
      break;
    case CURLOPT_PRIVATE: {
      const char *p = va_arg(arg, const char *);
      e->private_copy = p ? p : "";
      break;
    }
    case CURLOPT_ERRORBUFFER:
      e->error_buffer = va_arg(arg, char *);
      break;

    // Long-valued options that carry no meaning for a local filesystem. They
    // are accepted rather than rejected so the caller's parameter plumbing
    // (OmafCurlEasyHelper::setParams) keeps working unchanged.
    case CURLOPT_SSL_VERIFYPEER:
    case CURLOPT_SSL_VERIFYHOST:
    case CURLOPT_PROXYTYPE:
    case CURLOPT_NOPROGRESS:
    case CURLOPT_HTTPGET:
    case CURLOPT_FOLLOWLOCATION:
    case CURLOPT_HEADER:
    case CURLOPT_VERBOSE:
      (void)va_arg(arg, long);
      break;

    // String-valued options, also ignored.
    case CURLOPT_PROXY:
    case CURLOPT_NOPROXY:
    case CURLOPT_USERNAME:
    case CURLOPT_PASSWORD:
    case CURLOPT_USERAGENT:
    case CURLOPT_ACCEPT_ENCODING:
    // CURLOPT_HEADERDATA and CURLOPT_WRITEHEADER are the same enum value in
    // curl.h, so only one of them may appear in this switch.
    case CURLOPT_HEADERDATA:
      (void)va_arg(arg, const char *);
      break;

    default:
      fprintf(stderr, "[local_curl] unsupported CURLOPT %d\n", static_cast<int>(option));
      rc = CURLE_UNKNOWN_OPTION;
      break;
  }
  va_end(arg);
  return rc;
}

extern "C" CURLcode curl_easy_perform(CURL *handle) {
  EasyHandle *e = as_easy(handle);
  if (!e) return CURLE_BAD_FUNCTION_ARGUMENT;
  return perform_transfer(e);
}

extern "C" CURLcode curl_easy_getinfo(CURL *handle, CURLINFO info, ...) {
  EasyHandle *e = as_easy(handle);
  if (!e) return CURLE_BAD_FUNCTION_ARGUMENT;

  va_list arg;
  va_start(arg, info);
  CURLcode rc = CURLE_OK;

  switch (info) {
    case CURLINFO_RESPONSE_CODE:
      *va_arg(arg, long *) = e->response_code;
      break;
    case CURLINFO_CONTENT_LENGTH_DOWNLOAD_T:
      *va_arg(arg, curl_off_t *) = e->content_length_download;
      break;
    case CURLINFO_SIZE_DOWNLOAD_T:
      *va_arg(arg, curl_off_t *) = e->size_download;
      break;
    case CURLINFO_SPEED_DOWNLOAD_T:
      *va_arg(arg, curl_off_t *) = e->speed_download;
      break;
    case CURLINFO_TOTAL_TIME_T:
      *va_arg(arg, curl_off_t *) = e->total_time;
      break;
    case CURLINFO_NAMELOOKUP_TIME_T:
      *va_arg(arg, curl_off_t *) = e->namelookup_time;
      break;
    case CURLINFO_CONNECT_TIME_T:
      *va_arg(arg, curl_off_t *) = e->connect_time;
      break;
    case CURLINFO_APPCONNECT_TIME_T:
      *va_arg(arg, curl_off_t *) = e->appconnect_time;
      break;
    case CURLINFO_PRETRANSFER_TIME_T:
      *va_arg(arg, curl_off_t *) = e->pretransfer_time;
      break;
    case CURLINFO_STARTTRANSFER_TIME_T:
      *va_arg(arg, curl_off_t *) = e->starttransfer_time;
      break;
    case CURLINFO_REDIRECT_TIME_T:
      *va_arg(arg, curl_off_t *) = e->redirect_time;
      break;
    case CURLINFO_PRIVATE:
      *va_arg(arg, void **) = const_cast<char *>(e->private_copy.c_str());
      break;
    case CURLINFO_EFFECTIVE_URL:
      *va_arg(arg, char **) = const_cast<char *>(e->url.c_str());
      break;
    default:
      rc = CURLE_UNKNOWN_OPTION;
      break;
  }
  va_end(arg);
  return rc;
}

extern "C" void curl_easy_cleanup(CURL *handle) { delete as_easy(handle); }

// ---------------------------------------------------------------------------
// Multi interface
// ---------------------------------------------------------------------------

extern "C" CURLM *curl_multi_init(void) { return reinterpret_cast<CURLM *>(new (std::nothrow) MultiHandle()); }

extern "C" CURLMcode curl_multi_setopt(CURLM *multi_handle, CURLMoption option, ...) {
  MultiHandle *m = as_multi(multi_handle);
  if (!m) return CURLM_BAD_HANDLE;

  va_list arg;
  va_start(arg, option);
  CURLMcode rc = CURLM_OK;
  switch (option) {
    case CURLMOPT_MAXCONNECTS:
      m->maxconnects = va_arg(arg, long);
      break;
    default:
      rc = CURLM_UNKNOWN_OPTION;
      break;
  }
  va_end(arg);
  return rc;
}

extern "C" CURLMcode curl_multi_add_handle(CURLM *multi_handle, CURL *easy_handle) {
  MultiHandle *m = as_multi(multi_handle);
  EasyHandle *e = as_easy(easy_handle);
  if (!m || !e) return CURLM_BAD_HANDLE;
  if (e->in_multi) return CURLM_ADDED_ALREADY;
  e->in_multi = true;
  e->completed = false;  // a reused handle begins a fresh transfer
  m->handles.push_back(e);
  return CURLM_OK;
}

extern "C" CURLMcode curl_multi_remove_handle(CURLM *multi_handle, CURL *easy_handle) {
  MultiHandle *m = as_multi(multi_handle);
  EasyHandle *e = as_easy(easy_handle);
  if (!m || !e) return CURLM_BAD_HANDLE;
  m->handles.remove(e);
  e->in_multi = false;
  return CURLM_OK;
}

// Performs every pending transfer to completion and queues one CURLMSG_DONE per
// handle. Real libcurl would interleave partial progress across many calls, but
// a local read cannot block on the network, so completing eagerly is both
// simpler and strictly faster. The OMAF caller only requires that the DONE
// message eventually appears and that *running_handles reflects reality.
extern "C" CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles) {
  MultiHandle *m = as_multi(multi_handle);
  if (!m) {
    if (running_handles) *running_handles = 0;
    return CURLM_BAD_HANDLE;
  }

  for (EasyHandle *e : m->handles) {
    if (e->completed) continue;
    perform_transfer(e);
    e->completed = true;

    CURLMsg msg;
    msg.msg = CURLMSG_DONE;
    msg.easy_handle = reinterpret_cast<CURL *>(e);
    msg.data.result = e->result;
    m->messages.push_back(msg);
  }

  if (running_handles) *running_handles = 0;  // everything finishes inside this call
  return CURLM_OK;
}

extern "C" CURLMsg *curl_multi_info_read(CURLM *multi_handle, int *msgs_in_queue) {
  MultiHandle *m = as_multi(multi_handle);
  if (!m || m->messages.empty()) {
    if (msgs_in_queue) *msgs_in_queue = 0;
    return nullptr;
  }
  m->last_message = m->messages.front();
  m->messages.pop_front();
  if (msgs_in_queue) *msgs_in_queue = static_cast<int>(m->messages.size());
  return &m->last_message;
}

extern "C" CURLMcode curl_multi_wait(CURLM *multi_handle, struct curl_waitfd extra_fds[], unsigned int extra_nfds,
                                     int timeout_ms, int *numfds) {
  (void)multi_handle;
  (void)extra_fds;
  (void)extra_nfds;
  (void)timeout_ms;
  if (numfds) *numfds = 0;
  return CURLM_OK;
}

extern "C" CURLMcode curl_multi_cleanup(CURLM *multi_handle) {
  MultiHandle *m = as_multi(multi_handle);
  if (!m) return CURLM_BAD_HANDLE;
  for (EasyHandle *e : m->handles) e->in_multi = false;
  delete m;
  return CURLM_OK;
}

// ---------------------------------------------------------------------------
// Error strings (declared by curl.h; some OMAF logging paths use them)
// ---------------------------------------------------------------------------

extern "C" const char *curl_easy_strerror(CURLcode errornum) {
  switch (errornum) {
    case CURLE_OK:
      return "No error";
    case CURLE_RANGE_ERROR:
      return "Requested range was not delivered by the server";
    case CURLE_WRITE_ERROR:
      return "Failed writing received data to disk/application";
    case CURLE_FILE_COULDNT_READ_FILE:
      return "Couldn't read local file";
    case CURLE_URL_MALFORMAT:
      return "URL using bad/illegal format or missing URL";
    case CURLE_PARTIAL_FILE:
      return "A file transfer was shorter or larger than expected";
    case CURLE_OPERATION_TIMEDOUT:
      return "Timeout was reached";
    default:
      return "Unknown error";
  }
}

extern "C" const char *curl_multi_strerror(CURLMcode errornum) {
  switch (errornum) {
    case CURLM_OK:
      return "No error";
    case CURLM_BAD_HANDLE:
      return "Invalid multi handle";
    case CURLM_BAD_EASY_HANDLE:
      return "Invalid easy handle";
    case CURLM_UNKNOWN_OPTION:
      return "Unknown option";
    case CURLM_ADDED_ALREADY:
      return "The easy handle is already added to a multi handle";
    default:
      return "Unknown error";
  }
}
