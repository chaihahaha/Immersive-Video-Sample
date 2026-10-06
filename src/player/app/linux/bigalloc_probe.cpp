/*
 * bigalloc_probe.cpp
 *
 * Heap diagnostics for the wasm port.
 *
 * Established so far, by controlled experiment:
 *   - The wasm heap grows ~200 MB/s once the OMAF reader thread runs and hits
 *     the 4 GB ceiling in ~20 s. With index.html?stopReader=1 it stays flat at
 *     256 MB, so the growth lives entirely in the reader/download/parse path.
 *   - mallinfo().uordblks grows in step -> live data, not fragmentation.
 *   - 159 transfers delivering 1.7 MB produced 3.8 GB of growth, i.e. ~24 MB
 *     per downloaded segment. That figure is suspiciously close to one
 *     5120x3072 YUV420 picture (23.6 MB).
 *   - Accounting the C++ operators alone showed new/delete balanced, so the
 *     growth is in plain C malloc.
 *
 * `-Wl,--wrap=malloc` does not intercept anything under Emscripten (counters
 * stayed at zero). The supported way is to define the allocator entry points
 * ourselves and forward to emscripten_builtin_*, which is exactly what this
 * file does -- see emscripten/heap.h: "Use these to access that underlying
 * allocator when intercepting/wrapping the allocator API."
 *
 * Report from the page:
 *   Module.ccall('em_probe_report', null, ['string'], ['manual'])
 */

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
  fflush(stderr);
}

extern "C" PROBE_EXPORT int em_probe_live_kb(void) { return static_cast<int>(g_live_bytes / 1024); }

// ---------------------------------------------------------------------------
// Global allocator entry points.
//
// Defining these here overrides libc's versions for the whole program, so every
// malloc in OMAF and FFmpeg is accounted. emscripten_builtin_* reaches the real
// allocator underneath, so there is no recursion.
// ---------------------------------------------------------------------------

// Capture a call stack for large allocations, so whoever is leaking
// frame-sized buffers can be named instead of guessed at. Rate limited.
namespace {
const size_t kStackThreshold = 512u * 1024u;
const int kStackReportsMax = 40;
int g_stack_reports = 0;
thread_local bool t_in_stack_hook = false;

void report_large_alloc(size_t n) {
  if (n < kStackThreshold || g_stack_reports >= kStackReportsMax || t_in_stack_hook) return;
  t_in_stack_hook = true;
  ++g_stack_reports;
#ifdef __EMSCRIPTEN__
  char stack[3000];
  stack[0] = '\0';
  emscripten_get_callstack(EM_LOG_C_STACK | EM_LOG_JS_STACK | EM_LOG_DEMANGLE, stack, sizeof(stack));
  fprintf(stderr, "[bigalloc] #%d %zu KB\n%s\n", g_stack_reports, n / 1024, stack);
#else
  fprintf(stderr, "[bigalloc] #%d %zu KB\n", g_stack_reports, n / 1024);
#endif
  fflush(stderr);
  t_in_stack_hook = false;
}
}  // namespace

extern "C" void *malloc(size_t n) {
  report_large_alloc(n);
  void *p = emscripten_builtin_malloc(n);
  account_alloc(n, p);
  return p;
}

extern "C" void free(void *p) {
  if (p) account_free(p);
  emscripten_builtin_free(p);
}

extern "C" void *calloc(size_t n, size_t size) {
  const size_t total = n * size;
  void *p = emscripten_builtin_malloc(total);
  if (p) memset(p, 0, total);
  account_alloc(total, p);
  return p;
}

extern "C" void *realloc(void *p, size_t n) {
  if (p == nullptr) return malloc(n);
  const size_t old_usable = usable_of(p);
  // The builtin realloc is not exposed; emulate it.
  void *q = emscripten_builtin_malloc(n);
  if (q == nullptr) return nullptr;
  if (old_usable) memcpy(q, p, old_usable < n ? old_usable : n);
  account_free(p);
  emscripten_builtin_free(p);
  account_alloc(n, q);
  return q;
}

extern "C" void *memalign(size_t align, size_t n) {
  void *p = emscripten_builtin_memalign(align, n);
  account_alloc(n, p);
  return p;
}

extern "C" void *aligned_alloc(size_t align, size_t n) { return memalign(align, n); }

extern "C" void *valloc(size_t n) { return memalign(4096, n); }

// posix_memalign is what libc++/FFmpeg usually reach for.
extern "C" int posix_memalign(void **out, size_t align, size_t n) {
  void *p = emscripten_builtin_memalign(align, n);
  account_alloc(n, p);
  if (!p) return 12;  // ENOMEM
  *out = p;
  return 0;
}
