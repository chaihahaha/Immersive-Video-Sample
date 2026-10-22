/*
 * bigalloc_probe.cpp
 *
 * Heap diagnostics for the wasm port.
 *
 * Established, by controlled experiment:
 *   - The wasm heap grows ~200 MB/s once the OMAF reader thread runs and hits
 *     the 4 GB ceiling in ~20 s. With index.html?stopReader=1 it stays flat at
 *     256 MB, so the growth lives entirely in the reader/download/parse path.
 *   - mallinfo().uordblks grows in step -> live data, not fragmentation.
 *   - Accounting the C++ operators alone showed new/delete balanced, so the
 *     growth is in plain C malloc.
 *
 * `-Wl,--wrap=malloc` does not intercept anything under Emscripten (counters
 * stayed at zero). The supported way is to define the allocator entry points
 * ourselves and forward to emscripten_builtin_*, which is exactly what this
 * file does -- see emscripten/heap.h: "Use these to access that underlying
 * allocator when intercepting/wrapping the allocator API."
 *
 * What this file reports, from the page:
 *   Module.ccall('em_probe_report', null, ['string'], ['manual'])
 *
 *   1. Totals and log2 size buckets (live and cumulative).
 *   2. [site N]  a call site, printed once with its call stack, the first time
 *      it allocates a buffer of >= kBigAlloc bytes.
 *   3. [leaksite] live bytes per call site, largest first. This is the part
 *      that pins a leak: a site whose live bytes keep climbing while the
 *      counters next to it (e.g. merged produced/consumed) stay balanced is the
 *      leak.
 *
 * Tracking is limited to buffers >= kBigAlloc (512 KB), so the bookkeeping cost
 * is a few dozen map operations per frame at most.
 */

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <new>

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#include <emscripten/heap.h>
#define PROBE_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define PROBE_EXPORT
#endif

namespace {

const int kBuckets = 34;  // log2(size) buckets: 2^0 .. 2^33

volatile size_t g_live_bytes = 0;
volatile long g_live_count = 0;
volatile size_t g_total_bytes = 0;
volatile long g_total_count = 0;
volatile size_t g_max_live_block = 0;

volatile size_t g_live_bucket_bytes[kBuckets];
volatile long g_live_bucket_count[kBuckets];
volatile size_t g_ever_bucket_bytes[kBuckets];
volatile long g_ever_bucket_count[kBuckets];

inline int bucket_of(size_t n) {
  int b = 0;
  while (b < kBuckets - 1 && (static_cast<size_t>(1) << b) < n) ++b;
  return b;
}

inline void account_alloc(size_t requested, void *p) {
  if (!p) return;
  const size_t usable = malloc_usable_size(p);
  const int b = bucket_of(usable);
  g_live_bytes += usable;
  g_live_count++;
  g_total_bytes += usable;
  g_total_count++;
  g_live_bucket_bytes[b] += usable;
  g_live_bucket_count[b]++;
  g_ever_bucket_bytes[b] += usable;
  g_ever_bucket_count[b]++;
  if (usable > g_max_live_block) g_max_live_block = usable;
  (void)requested;
}

inline void account_free(void *p) {
  if (!p) return;
  const size_t usable = malloc_usable_size(p);
  const int b = bucket_of(usable);
  g_live_bytes -= usable;
  g_live_count--;
  g_live_bucket_bytes[b] -= usable;
  g_live_bucket_count[b]--;
}

size_t usable_of(void *p) { return p ? malloc_usable_size(p) : 0; }

// ---------------------------------------------------------------------------
// Live tracking of big buffers, per call site.
//
// The table is static so that bookkeeping never recurses into malloc, and the
// whole thing is guarded by one small spin lock: allocations of this size are
// rare (tens per second), so contention is irrelevant.
// ---------------------------------------------------------------------------

const size_t kBigAlloc = 512u * 1024u;  // track buffers at least this big
const int kSlots = 8192;                // ~2000 live big buffers expected
const int kMaxSites = 64;
const int kMaxSiteStacks = 24;

struct Slot {
  void *p;  // nullptr = empty, kTombstone = deleted
  size_t usable;
  int site;
};

struct SiteStat {
  char key[512];    // first few C frames, used as the identity of the site
  char label[280];  // one-line version, for the summary table
  long live_count;
  size_t live_bytes;
  size_t peak_live_bytes;
  long ever_count;
  bool stack_printed;
};

Slot g_slots[kSlots];
SiteStat g_sites[kMaxSites];
int g_site_count = 0;
int g_site_overflow = 0;  // blocks tracked after the site table filled up

std::atomic<int> g_lock(0);
thread_local bool t_in_hook = false;

inline void lock_table() {
  int expected = 0;
  while (!g_lock.compare_exchange_weak(expected, 1, std::memory_order_acquire)) {
    expected = 0;
  }
}

inline void unlock_table() { g_lock.store(0, std::memory_order_release); }

inline size_t slot_hash(void *p) {
  size_t h = reinterpret_cast<size_t>(p);
  h ^= h >> 7;
  h *= 2654435761u;
  return h & (kSlots - 1);
}

void *const kTombstone = reinterpret_cast<void *>(1);

int site_for(const char *key, const char *label) {
  for (int i = 0; i < g_site_count; ++i) {
    if (strcmp(g_sites[i].key, key) == 0) return i;
  }
  if (g_site_count >= kMaxSites) {
    g_site_overflow++;
    return kMaxSites - 1;  // fold the overflow into the last slot
  }
  const int idx = g_site_count++;
  snprintf(g_sites[idx].key, sizeof(g_sites[idx].key), "%s", key);
  snprintf(g_sites[idx].label, sizeof(g_sites[idx].label), "%s", label);
  g_sites[idx].live_count = 0;
  g_sites[idx].live_bytes = 0;
  g_sites[idx].peak_live_bytes = 0;
  g_sites[idx].ever_count = 0;
  g_sites[idx].stack_printed = false;
  return idx;
}

// The full call stack is printed the first time a site shows up, so the label
// used in the live table can be matched to code.
void label_site_once(int idx) {
  if (g_sites[idx].stack_printed) return;
  g_sites[idx].stack_printed = true;
  if (idx >= kMaxSiteStacks) return;  // keep the console bounded
#ifdef __EMSCRIPTEN__
  char stack[1600];
  stack[0] = '\0';
  emscripten_get_callstack(EM_LOG_C_STACK | EM_LOG_JS_STACK, stack, sizeof(stack));
  fprintf(stderr, "[site %d] first big allocation, stack:\n%s\n", idx, stack);
#else
  fprintf(stderr, "[site %d] first big allocation (%s)\n", idx, g_sites[idx].label);
#endif
  fflush(stderr);
}

// __builtin_return_address is not usable here: Emscripten aborts without
// -sUSE_OFFSET_CONVERTER, so the call stack is captured instead and hashed down
// to a short identity string. This runs a few dozen times per second at most.
void capture_site(char *key, size_t key_size, char *label, size_t label_size) {
  key[0] = '\0';
  label[0] = '\0';
#ifdef __EMSCRIPTEN__
  char stack[2500];
  stack[0] = '\0';
  emscripten_get_callstack(EM_LOG_C_STACK | EM_LOG_JS_STACK, stack, sizeof(stack));
  // Keep only the wasm frames: the JS frames above them are identical for every
  // site (they all come through the same import), so they cannot identify one.
  size_t used = 0;
  size_t label_used = 0;
  int frames = 0;
  const char *p = stack;
  while (*p) {
    const char *nl = strchr(p, '\n');
    const size_t len = nl ? static_cast<size_t>(nl - p) : strlen(p);
    // Skip the frames of the probe itself plus the allocator shims: they are
    // identical for every site and would otherwise be the whole key. The stack
    // lines look like "    at <symbol> (https://.../render.wasm?...)".
    static const char *kSkip[] = {
        "capture_site",     "label_site_once",      "track_alloc",
        "maybe_track_alloc", "imports.<computed>",  "render.js:",
        "malloc (",         "calloc (",             "realloc (",
        "memalign",         "operator new(",        "operator new (",
    };
    bool skip_frame = false;
    for (size_t k = 0; k < sizeof(kSkip) / sizeof(kSkip[0]); ++k) {
      if (memmem(p, len, kSkip[k], strlen(kSkip[k])) != nullptr) {
        skip_frame = true;
        break;
      }
    }
    if (skip_frame) {
      if (!nl) break;
      p = nl + 1;
      continue;
    }
    if (memmem(p, len, "render.wasm", 11) != nullptr) {
      size_t start = 0;
      while (start < len && (p[start] == ' ' || p[start] == '\t')) ++start;
      size_t end = len;
      // Drop the trailing "(https://host:port/render.wasm?...)" noise.
      const char *paren = static_cast<const char *>(memmem(p + start, end - start, " (https://", 10));
      if (paren) end = static_cast<size_t>(paren - p);
      const size_t frame_len = end - start;
      if (frame_len > 0 && used + frame_len + 2 < key_size) {
        memcpy(key + used, p + start, frame_len);
        used += frame_len;
        key[used++] = '\n';
        key[used] = '\0';
        if (label_used + frame_len + 5 < label_size) {
          const int n = snprintf(label + label_used, label_size - label_used, "%s%.*s",
                                 label_used ? " <- " : "", static_cast<int>(frame_len), p + start);
          if (n > 0) label_used += static_cast<size_t>(n);
          if (label_used >= label_size) label_used = label_size - 1;
        }
        ++frames;
        if (frames >= 3) break;
      }
    }
    if (!nl) break;
    p = nl + 1;
  }
  if (key[0] == '\0') snprintf(key, key_size, "no-wasm-frame");
#else
  snprintf(key, key_size, "unknown");
#endif
  if (label[0] == '\0') snprintf(label, label_size, "unlabeled");
}

// Records a live big buffer.
void track_alloc(void *p, size_t usable) {
  char key[512];
  char label[280];
  capture_site(key, sizeof(key), label, sizeof(label));
  lock_table();
  const int site = site_for(key, label);
  const size_t start = slot_hash(p);
  int tomb = -1;
  for (int probes = 0; probes < kSlots; ++probes) {
    const size_t at = (start + probes) & (kSlots - 1);
    Slot &s = g_slots[at];
    if (s.p == p) break;  // already present (should not happen)
    if (s.p == kTombstone) {
      if (tomb < 0) tomb = static_cast<int>(at);
      continue;
    }
    if (s.p == nullptr) {
      Slot &dst = g_slots[tomb >= 0 ? tomb : static_cast<int>(at)];
      dst.p = p;
      dst.usable = usable;
      dst.site = site;
      SiteStat &st = g_sites[site];
      st.live_count++;
      st.live_bytes += usable;
      st.ever_count++;
      if (st.live_bytes > st.peak_live_bytes) st.peak_live_bytes = st.live_bytes;
      label_site_once(site);
      unlock_table();
      return;
    }
  }
  unlock_table();
}

void track_free(void *p) {
  lock_table();
  const size_t start = slot_hash(p);
  for (int probes = 0; probes < kSlots; ++probes) {
    Slot &s = g_slots[(start + probes) & (kSlots - 1)];
    if (s.p == nullptr) break;
    if (s.p == p) {
      SiteStat &st = g_sites[s.site];
      st.live_count--;
      st.live_bytes -= s.usable;
      s.p = kTombstone;
      s.usable = 0;
      break;
    }
  }
  unlock_table();
}

inline void maybe_track_alloc(void *p, size_t requested) {
  if (p == nullptr || requested < kBigAlloc) return;
  track_alloc(p, usable_of(p));
}

inline void maybe_track_free(void *p, size_t usable) {
  if (p == nullptr || usable < kBigAlloc) return;
  track_free(p);
}

}  // namespace

extern "C" PROBE_EXPORT void em_probe_report(const char *tag) {
  struct mallinfo mi = mallinfo();
  fprintf(stderr,
          "[probe %s] mallinfo arena=%d uordblks=%d fordblks=%d | malloc live=%zu KB in %ld blocks, "
          "ever=%zu KB in %ld blocks, largest live=%zu KB\n",
          tag ? tag : "", mi.arena, mi.uordblks, mi.fordblks, g_live_bytes / 1024, g_live_count,
          g_total_bytes / 1024, g_total_count, g_max_live_block / 1024);
  for (int b = 8; b < kBuckets; ++b) {
    if (g_live_bucket_count[b] == 0 && g_ever_bucket_count[b] == 0) continue;
    fprintf(stderr,
            "[probe %s]   2^%-2d live=%9zu KB / %7ld blocks    ever=%9zu KB / %7ld blocks\n",
            tag ? tag : "", b, g_live_bucket_bytes[b] / 1024, g_live_bucket_count[b],
            g_ever_bucket_bytes[b] / 1024, g_ever_bucket_count[b]);
  }

  int order[kMaxSites];
  int n = 0;
  lock_table();
  for (int i = 0; i < g_site_count; ++i) order[n++] = i;
  unlock_table();
  // Insertion sort, largest live bytes first: at most kMaxSites entries.
  for (int i = 1; i < n; ++i) {
    const int key = order[i];
    int j = i - 1;
    while (j >= 0 && g_sites[order[j]].live_bytes < g_sites[key].live_bytes) {
      order[j + 1] = order[j];
      --j;
    }
    order[j + 1] = key;
  }
  fprintf(stderr, "[leaksite %s] live buffers >= %zu KB, %d sites%s\n", tag ? tag : "",
          kBigAlloc / 1024, g_site_count,
          g_site_overflow ? " (site table overflowed)" : "");
  for (int i = 0; i < n; ++i) {
    const SiteStat &st = g_sites[order[i]];
    if (st.ever_count == 0) continue;
    fprintf(stderr,
            "[leaksite %s]   #%d live=%8zu KB / %5ld blocks  peak=%8zu KB  ever=%5ld  %s\n",
            tag ? tag : "", order[i], st.live_bytes / 1024, st.live_count,
            st.peak_live_bytes / 1024, st.ever_count, st.label);
  }
  fflush(stderr);
}

extern "C" PROBE_EXPORT int em_probe_live_kb(void) { return static_cast<int>(g_live_bytes / 1024); }

// Live KB held by tracked buffers (>= 512 KB), so the render loop can print it
// next to the heap size without a full report.
extern "C" PROBE_EXPORT int em_probe_big_live_kb(void) {
  size_t total = 0;
  lock_table();
  for (int i = 0; i < g_site_count; ++i) total += g_sites[i].live_bytes;
  unlock_table();
  return static_cast<int>(total / 1024);
}

// ---------------------------------------------------------------------------
// Global allocator entry points.
//
// Defining these here overrides libc's versions for the whole program, so every
// malloc in OMAF and FFmpeg is accounted. emscripten_builtin_* reaches the real
// allocator underneath, so there is no recursion.
// ---------------------------------------------------------------------------

extern "C" void *malloc(size_t n) {
  void *p = emscripten_builtin_malloc(n);
  if (!t_in_hook) {
    t_in_hook = true;
    account_alloc(n, p);
    maybe_track_alloc(p, n);
    t_in_hook = false;
  }
  return p;
}

extern "C" void free(void *p) {
  if (p != nullptr && !t_in_hook) {
    t_in_hook = true;
    const size_t usable = usable_of(p);
    account_free(p);
    maybe_track_free(p, usable);
    t_in_hook = false;
  }
  emscripten_builtin_free(p);
}

extern "C" void *calloc(size_t n, size_t size) {
  const size_t total = n * size;
  void *p = emscripten_builtin_malloc(total);
  if (p) memset(p, 0, total);
  if (!t_in_hook) {
    t_in_hook = true;
    account_alloc(total, p);
    maybe_track_alloc(p, total);
    t_in_hook = false;
  }
  return p;
}

extern "C" void *realloc(void *p, size_t n) {
  if (p == nullptr) return malloc(n);
  const size_t old_usable = usable_of(p);
  // Keep the block when it already fits and is not wildly oversized: this is
  // what std::vector/std::string growth expects, and it avoids churn.
  if (old_usable >= n && old_usable <= n + (n >> 2)) return p;
  // The builtin realloc is not exposed; emulate it.
  void *q = emscripten_builtin_malloc(n);
  if (q == nullptr) return nullptr;
  if (old_usable) memcpy(q, p, old_usable < n ? old_usable : n);
  if (!t_in_hook) {
    t_in_hook = true;
    maybe_track_free(p, old_usable);
    account_free(p);
    account_alloc(n, q);
    maybe_track_alloc(q, n);
    t_in_hook = false;
  }
  emscripten_builtin_free(p);
  return q;
}

extern "C" void *memalign(size_t align, size_t n) {
  void *p = emscripten_builtin_memalign(align, n);
  if (!t_in_hook) {
    t_in_hook = true;
    account_alloc(n, p);
    maybe_track_alloc(p, n);
    t_in_hook = false;
  }
  return p;
}

extern "C" void *aligned_alloc(size_t align, size_t n) { return memalign(align, n); }

extern "C" void *valloc(size_t n) { return memalign(4096, n); }

// posix_memalign is what libc++/FFmpeg usually reach for.
extern "C" int posix_memalign(void **out, size_t align, size_t n) {
  void *p = emscripten_builtin_memalign(align, n);
  if (!p) return 12;  // ENOMEM
  if (!t_in_hook) {
    t_in_hook = true;
    account_alloc(n, p);
    maybe_track_alloc(p, n);
    t_in_hook = false;
  }
  *out = p;
  return 0;
}
