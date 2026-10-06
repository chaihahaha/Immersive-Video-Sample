/*
 * Copyright (c) 2019, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.

 *
 */

//!
//! \file     render.cpp
//! \brief    This is the main function for the application.
//!

#ifdef _LINUX_OS_

#include <functional>
#include <emscripten.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <thread>
#include "../../../utils/tinyxml2.h"
#include "../../player_lib/Common/Common.h"
#include "../../player_lib/Api/MediaPlayer_Linux.h"
#include "../../player_lib/Render/RenderContext.h"
#include "GLFWRenderContext.h"

// Implemented in src/OmafDashAccess/local_curl/local_curl.cpp. Declares where
// the preloaded content directory is so segment URLs can be resolved to files
// in the Emscripten virtual filesystem.
extern "C" void em_local_curl_set_root(const char *root);
extern "C" void em_local_curl_set_http_base(const char *base);
extern "C" int em_local_curl_prefetch(const char *url);
// Aggregate delivery cap in bytes/second (0 = unlimited). Without it the reader
// thread consumes the whole presentation in seconds and the wasm heap fills up.
extern "C" void em_local_curl_set_rate_limit(double bytes_per_second);
// Debug switches owned by OmafDashSource (see omaf_debug_set_stop_reader).
extern "C" void omaf_debug_set_stop_reader(int v);
extern "C" void omaf_debug_set_stop_stitch(int v);
extern "C" void omaf_debug_set_stop_decode(int v);
extern "C" void omaf_debug_set_no_upload(int v);
extern "C" void omaf_debug_set_no_gl(int v);

// Reads a flag from window.__flags in the page, so behaviour can be bisected
// from the URL without rebuilding: index.html?stopReader=1
EM_JS(int, ivs_js_flag, (const char *name), {
  if (typeof window === 'undefined' || !window.__flags) return 0;
  return window.__flags[UTF8ToString(name)] ? 1 : 0;
});

// Default HTTP content location: <page origin>/Gaslamp, i.e. the same server
// that served index.html. Used when neither config.xml nor ?contentBase= says
// otherwise, so the non-preloaded build works with no configuration at all.
EM_JS(int, ivs_default_content_base, (char *out, int cap), {
  if (typeof window === 'undefined' || !window.location || cap <= 0) return 0;
  var v = window.location.origin + '/Gaslamp';
  var n = lengthBytesUTF8(v);
  if (n > cap - 1) n = cap - 1;
  stringToUTF8(v, out, n + 1);
  return n;
});

// Reads a string flag from window.__flags, e.g.
//   index.html?contentBase=http://127.0.0.1:8123/Gaslamp
// Returns the length written, or 0 if the flag is absent. Lets the content
// source be switched at runtime instead of being baked into config.xml.
EM_JS(int, ivs_js_string, (const char *name, char *out, int cap), {
  if (typeof window === 'undefined' || !window.__flags || cap <= 0) return 0;
  var v = window.__flags[UTF8ToString(name)];
  if (!v) return 0;
  var n = lengthBytesUTF8(v);
  if (n > cap - 1) n = cap - 1;
  stringToUTF8(v, out, n + 1);
  return n;
});

#define MAXFOV 140
#define MINFOV 50
#define MAXVIEWPORTLEN 2000
#define MINVIEWPORTLEN 800
#define MAXWINDOWLEN 2000
#define MINWINDOWLEN 500


VCD_USE_VRVIDEO;
using namespace tinyxml2;

std::string config_string = R"(
<?xml version="1.0"?>
<info>
    <!-- windowWidth/windowHeight is for width and height of window -->
    <windowWidth>960</windowWidth>
    <windowHeight>960</windowHeight>
    <!-- Resource URL, can be remote or local.
         A URL WITHOUT a scheme selects OMAF's "local media" mode: no HTTP
         client is created outside the virtual filesystem, and the MPD plus all
         segments are read from --preload-file content through local_curl.
         (An http:// URL would additionally require MPDInfo::baseURL to contain
         an "IP:port", which this MPD's "/VOD8K/" base does not.) -->
    <url>/Gaslamp/Test.mpd</url>
    <!-- sourceType 0 is for DashSource -->
    <sourceType>0</sourceType>
    <!-- enableExtractor 0 is false and 1 is true -->
    <enableExtractor>0</enableExtractor>
    <!-- enableAutoView 0 is false and 1 is true in MultiView mode -->
    <enableAutoView>0</enableAutoView>
    <!-- debug option to dump input packets -->
    <StreamDumpedOption>0</StreamDumpedOption>
    <!-- viewport settings -->
    <viewportHFOV>80</viewportHFOV>
    <viewportVFOV>80</viewportVFOV>
    <viewportWidth>960</viewportWidth>
    <viewportHeight>960</viewportHeight>
    <!-- cache path -->
    <cachePath>/Gaslamp</cachePath>
    <!-- Optional HTTP base URL for content that is NOT preloaded into the
         virtual filesystem. When set, local_curl fetches any resource it cannot
         find in the VFS from here, so the mp4 files can be served by an ordinary
         web server instead of being baked into render.data. This saves the
         ~57 MB of MEMFS content from the browser's JS heap (it is not wasm
         memory) and means content can change without recompiling. Example, for
         tools/serve_wasm.py running on port 8123:
             <contentBaseUrl>http://127.0.0.1:8123/Gaslamp</contentBaseUrl>
         Leave empty for the purely filesystem-backed build. -->
    <contentBaseUrl></contentBaseUrl>
    <!-- Pacing for the local-filesystem curl backend, in bytes per second.
         The content is about 400 KB/s of video, so this is ~2x real time: fast
         enough to buffer ahead, slow enough that the reader thread cannot race
         hundreds of segments past the renderer. 0 disables the cap. -->
    <localRateLimitBytesPerSec>1048576</localRateLimitBytesPerSec>
    <!-- log level: INFO < WARNING < ERROR < FATAL -->
    <minLogLevel>WARNING</minLogLevel>
    <!-- limited video decoder resolution -->
    <maxVideoDecodeWidth>2560</maxVideoDecodeWidth>
    <maxVideoDecodeHeight>2560</maxVideoDecodeHeight>
    <!-- for WebRTC parameters -->
    <resolution>8k</resolution>
    <server_url>http://127.0.0.1</server_url>
    <ProjectionType>ERP</ProjectionType>
    <frameRate>30</frameRate>
    <frameNum>100</frameNum>
    <enableDump>false</enableDump>
    <predict enable="0">
     <!-- <plugin>libViewportPredict_LR.so</plugin>
     <path>../plugins/ViewportPredict_Plugin/predict_LR/</path> -->
    </predict>
    <intimeviewportupdate enable="0">
     <responseTimesInOneSeg>2</responseTimesInOneSeg>
     <maxCatchupWidth>2560</maxCatchupWidth>
     <maxCatchupHeight>2560</maxCatchupHeight>
    </intimeviewportupdate>
    <!-- <PathOf360SCVPPlugins>/usr/local/lib/libPanZoomTileSelection.so</PathOf360SCVPPlugins> -->
</info>
)";

struct RenderConfig renderConfig;
volatile bool configLoaded = false;
MediaPlayer_Linux *player = new MediaPlayer_Linux();
//RenderContext* context; // TODO: buggy it's overwritten by new


bool parseRenderFromXml(std::string xml_file, struct RenderConfig &renderConfig) noexcept {
  try {
    XMLDocument config;
    config.LoadFile(xml_file.c_str());
    XMLElement *info = config.RootElement();
    if (NULL == info)
    {
      LOG(ERROR) << " XML parse failed! " << std::endl;
      return RENDER_ERROR;
    }
    XMLElement* wWidthElem = info->FirstChildElement("windowWidth");
    XMLElement* wHeightElem = info->FirstChildElement("windowHeight");
    if (wWidthElem != NULL && wHeightElem != NULL)
    {
      renderConfig.windowWidth = atoi(wWidthElem->GetText());
      renderConfig.windowHeight = atoi(wHeightElem->GetText());
      if (renderConfig.windowWidth < MINWINDOWLEN || renderConfig.windowWidth > MAXWINDOWLEN ||
          renderConfig.windowHeight < MINWINDOWLEN || renderConfig.windowHeight > MAXWINDOWLEN) {
        LOG(ERROR) << "---XML input invalid--- window width or height must be in range (" << MINWINDOWLEN << "-"
                  << MAXWINDOWLEN << ")!" << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for windowWidth OR windowHeight! " << std::endl;
      return RENDER_ERROR;
    }
    // Optional pacing knob for the local-filesystem curl backend.
    // Without it the reader thread pulls the entire presentation in seconds and
    // the resulting backlog exhausts the WebAssembly heap.
    renderConfig.localRateLimitBytesPerSec = 0;
    XMLElement* rateElem = info->FirstChildElement("localRateLimitBytesPerSec");
    if (rateElem != NULL && rateElem->GetText() != NULL)
    {
      renderConfig.localRateLimitBytesPerSec = (uint32_t)atoll(rateElem->GetText());
    }

    XMLElement* urlElem = info->FirstChildElement("url");
    if (urlElem != NULL)
    {
      renderConfig.url = new char[1024];
      memset_s(renderConfig.url, 1024*sizeof(char), 0);
      int n = std::min(int(strlen(urlElem->GetText())), 1024 - 1);
      memcpy_s(renderConfig.url, n * sizeof(char), (char *)urlElem->GetText(), n * sizeof(char));
      // check url is "mpd" or not
      if ((n <= 3) || (n - 3 > 0 && (renderConfig.url[n-1] != 'd' || renderConfig.url[n-2] != 'p' || renderConfig.url[n-3] != 'm'))) {
        LOG(ERROR) << "---INVALID url input! (only remote mpd file supported)---" << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for url! " << std::endl;
      return RENDER_ERROR;
    }
    XMLElement* stElem = info->FirstChildElement("sourceType");
    if (stElem != NULL)
    {
      renderConfig.sourceType =
        atoi(stElem->GetText());  // FFMPEG_SOURCE=1 or DASH_SOURCE=0
      if (renderConfig.sourceType > 2 || renderConfig.sourceType < 0) {
        LOG(ERROR) << "---INVALID source type input (0:remote mpd 2:webrtc support)---" << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for sourceType! " << std::endl;
      return RENDER_ERROR;
    }

    XMLElement* exElem = info->FirstChildElement("enableExtractor");
    if (exElem != NULL)
    {
      renderConfig.enableExtractor =
        atoi(exElem
                 ->GetText());  // 1: for LaterBinding 0: for extractor track
      if (renderConfig.enableExtractor != 0 && renderConfig.enableExtractor != 1) {
        LOG(ERROR) << "---INVALID enableExtractor input (1: for LaterBinding 0: for extractor track)---" << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for enableExtractor! " << std::endl;
      return RENDER_ERROR;
    }

    XMLElement* autoElem = info->FirstChildElement("enableAutoView");
    if (autoElem != NULL)
    {
      renderConfig.enableAutoView =
        atoi(autoElem
                 ->GetText());  // 1: for LaterBinding 0: for extractor track
      if (renderConfig.enableAutoView != 0 && renderConfig.enableAutoView != 1) {
        LOG(ERROR) << "---INVALID enableAutoView input (1: for auto view 0: for manual view)---" << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for enableAutoView! " << std::endl;
      return RENDER_ERROR;
    }

    XMLElement* hFOVElem = info->FirstChildElement("viewportHFOV");
    XMLElement* vFOVElem = info->FirstChildElement("viewportVFOV");
    if (hFOVElem != NULL && vFOVElem != NULL)
    {
      renderConfig.viewportHFOV = atoi(hFOVElem->GetText());
      renderConfig.viewportVFOV = atoi(vFOVElem->GetText());
      if (renderConfig.viewportHFOV < MINFOV || renderConfig.viewportHFOV > MAXFOV ||
        renderConfig.viewportVFOV < MINFOV || renderConfig.viewportVFOV > MAXFOV)
      {
        LOG(ERROR) << "---INVALID viewportHFOV or viewportVFOV input!---" << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for viewportHFOV or viewportVFOV! " << std::endl;
      return RENDER_ERROR;
    }
    XMLElement* vWidthElem = info->FirstChildElement("viewportWidth");
    XMLElement* vHeightElem = info->FirstChildElement("viewportHeight");
    if (vWidthElem != NULL && vHeightElem != NULL)
    {
      renderConfig.viewportWidth = atoi(vWidthElem->GetText());
      renderConfig.viewportHeight = atoi(vHeightElem->GetText());
      if (renderConfig.viewportWidth < MINVIEWPORTLEN || renderConfig.viewportWidth > MAXVIEWPORTLEN ||
          renderConfig.viewportHeight < MINVIEWPORTLEN || renderConfig.viewportHeight > MAXVIEWPORTLEN) {
        LOG(ERROR) << "---INVALID viewportWidth or viewportHeight input! (reference-960/960 or 1024/1024)---"
                  << std::endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for viewportWidth or viewportHeight! " << std::endl;
      return RENDER_ERROR;
    }
    XMLElement* pathElem = info->FirstChildElement("cachePath");
    if (pathElem != NULL)
    {
      renderConfig.cachePath = new char[1024];
      memset_s(renderConfig.cachePath, 1024 * sizeof(char), 0);
      int n = std::min(int(strlen(pathElem->GetText())), 1024 -1);
      memcpy_s(renderConfig.cachePath, n * sizeof(char), (char *)pathElem->GetText(), n * sizeof(char));
    }
    else
    {
      LOG(ERROR) << " invalid params for cachePath! " << std::endl;
      return RENDER_ERROR;
    }
    // Optional: serve content that is not preloaded from an HTTP base instead.
    // Absent or empty means "filesystem only", which is the original behaviour.
    renderConfig.contentBaseUrl = new char[1024];
    memset_s(renderConfig.contentBaseUrl, 1024 * sizeof(char), 0);
    XMLElement* baseUrlElem = info->FirstChildElement("contentBaseUrl");
    if (baseUrlElem != NULL && baseUrlElem->GetText() != NULL)
    {
      int n = std::min(int(strlen(baseUrlElem->GetText())), 1024 - 1);
      memcpy_s(renderConfig.contentBaseUrl, n * sizeof(char),
               (char *)baseUrlElem->GetText(), n * sizeof(char));
    }
    XMLElement* maxWidthElement = info->FirstChildElement("maxVideoDecodeWidth");
    XMLElement* maxHeightElement = info->FirstChildElement("maxVideoDecodeHeight");
    if (nullptr == maxWidthElement || nullptr == maxHeightElement)
    {
      return RENDER_ERROR;
    }
    renderConfig.maxVideoDecodeWidth = atoi(maxWidthElement->GetText());  // limited video decoder width of device.
    if (renderConfig.maxVideoDecodeWidth <= 0 || renderConfig.maxVideoDecodeWidth >= UINT32_MAX) {
      LOG(ERROR) << "---INVALID maxVideoDecodeWidth input---" << std::endl;
      return RENDER_ERROR;
    }
    renderConfig.maxVideoDecodeHeight = atoi(maxHeightElement->GetText());  // limited video decoder height of device.
    if (renderConfig.maxVideoDecodeHeight <= 0 || renderConfig.maxVideoDecodeHeight >= UINT32_MAX) {
      LOG(ERROR) << "---INVALID maxVideoDecodeHeight input---" << std::endl;
      return RENDER_ERROR;
    }
    XMLElement* viewportHFOVElement = info->FirstChildElement("viewportHFOV");
    XMLElement* viewportVFOVElement = info->FirstChildElement("viewportVFOV");
    if (nullptr == viewportHFOVElement || nullptr == viewportVFOVElement)
    {
      return RENDER_ERROR;
    }
    renderConfig.viewportHFOV = atoi(viewportHFOVElement->GetText());
    renderConfig.viewportVFOV = atoi(viewportVFOVElement->GetText());
    if (renderConfig.viewportHFOV < MINFOV || renderConfig.viewportHFOV > MAXFOV ||
        renderConfig.viewportVFOV < MINFOV || renderConfig.viewportVFOV > MAXFOV) {
      LOG(ERROR) << "---INVALID viewportHFOV or viewportVFOV input!---" << std::endl;
      return RENDER_ERROR;
    }

    XMLElement* logLevelElem = info->FirstChildElement("minLogLevel");
    if (logLevelElem != NULL)
    {
      std::string logLevel = logLevelElem->GetText();
      if (logLevel == "INFO")
      {
      }
      else if (logLevel == "WARNING")
      {
      }
      else if (logLevel == "ERROR")
      {
      }
      else if (logLevel == "FATAL")
      {
      }
      else
      {
        LOG(ERROR) << "Invalid min log level setting!" << endl;
        return RENDER_ERROR;
      }
    }
    else
    {
      LOG(ERROR) << " invalid params for minLogLevel! " << std::endl;
      return RENDER_ERROR;
    }

    // predictor option
    XMLElement *predictor = info->FirstChildElement("predict");
    if (predictor) {
      const XMLAttribute *enable = predictor->FirstAttribute();
      if (NULL == enable) return RENDER_ERROR;
      renderConfig.enablePredictor = atoi(enable->Value());
      renderConfig.predictPluginName = (char *)"";
      renderConfig.libPath = (char *)"";
      XMLElement* pluginElem = predictor->FirstChildElement("plugin");
      XMLElement* pPathElem = predictor->FirstChildElement("path");
      if (renderConfig.enablePredictor) {
        if (pluginElem != NULL && pPathElem != NULL)
        {
          renderConfig.predictPluginName = new char[1024];
          memcpy_s(renderConfig.predictPluginName, 1024, (char *)pluginElem->GetText(), 1024);
          renderConfig.libPath = new char[1024];
          memcpy_s(renderConfig.libPath, 1024, (char *)pPathElem->GetText(), 1024);
        }
        else
        {
          LOG(ERROR) << "Invalid plugin name or path!" << endl;
          return RENDER_ERROR;
        }
      }
    }

    // in time viewport update option
    XMLElement *viewportUpdate = info->FirstChildElement("intimeviewportupdate");
    if (viewportUpdate) {
      const XMLAttribute *enable = viewportUpdate->FirstAttribute();
      if (NULL == enable) return RENDER_ERROR;
      renderConfig.enableInTimeViewportUpdate = atoi(enable->Value());
      renderConfig.maxResponseTimesInOneSeg = 0;
      renderConfig.maxCatchupWidth = 0;
      renderConfig.maxCatchupHeight = 0;
      XMLElement* responseElem = viewportUpdate->FirstChildElement("responseTimesInOneSeg");
      XMLElement* maxWidthElem = viewportUpdate->FirstChildElement("maxCatchupWidth");
      XMLElement* maxHeightElem = viewportUpdate->FirstChildElement("maxCatchupHeight");
      if (renderConfig.enableInTimeViewportUpdate) {
        if (responseElem != NULL && maxWidthElem != NULL && maxHeightElem != NULL)
        {
          renderConfig.maxResponseTimesInOneSeg = atoi(responseElem->GetText());
          renderConfig.maxCatchupWidth = atoi(maxWidthElem->GetText());
          renderConfig.maxCatchupHeight = atoi(maxHeightElem->GetText());
        }
        else
        {
          LOG(ERROR) << "Invalid params in viewport update!" << endl;
          return RENDER_ERROR;
        }
      }
    }

    // PathOf360SCVPPlugins
    XMLElement* pathof360SCVPPlugin = info->FirstChildElement("PathOf360SCVPPlugins");
    if (pathof360SCVPPlugin != NULL)
    {
      renderConfig.pathof360SCVPPlugin = new char[1024];
      memcpy_s(renderConfig.pathof360SCVPPlugin, 1024, (char *)pathof360SCVPPlugin->GetText(), 1024);
    }
    else
    {
      renderConfig.pathof360SCVPPlugin = nullptr;
      // LOG(INFO) << " not settings for PathOf360SCVPPlugins! " << std::endl;
    }

    return RENDER_STATUS_OK;
  } catch (const std::exception &ex) {
    LOG(ERROR) << "Exception when parse the file: " << xml_file << std::endl;
    LOG(ERROR) << "Exception: " << ex.what() << std::endl;
    return RENDER_ERROR;
  }
}


RenderContext* InitRenderContext(struct RenderConfig config)
{
  RenderContext *context = new GLFWRenderContext(config);
  if (context == nullptr)
  {
      std::cout << "context nullptr" << std::endl;
    return nullptr;
  }
  void *window = context->InitContext();
  if (window == nullptr)
  {
      std::cout << "widow nullptr" << std::endl;
    SAFE_DELETE(context);
    return nullptr;
  }
  return context;
}

// ---------------------------------------------------------------------------
// Diagnostic: the player writes ~9000 lines/second to std::cout, and the wasm
// heap grows roughly 30-50 KB per line until it hits the 4 GB ceiling. Redirect
// std::cout to a discarding buffer to find out whether the logging path is what
// allocates. Set IVS_SILENCE_STDOUT to 0 to get the logs back.
// ---------------------------------------------------------------------------
#define IVS_SILENCE_STDOUT 0

#if IVS_SILENCE_STDOUT
namespace {
class NullStreamBuf : public std::streambuf {
 protected:
  int overflow(int c) override { return c; }
  std::streamsize xsputn(const char *, std::streamsize n) override { return n; }
};
NullStreamBuf g_null_buf;
}  // namespace
#endif

// Heap accounting hook, implemented in bigalloc_probe.cpp.
extern "C" void em_probe_report(const char *tag);

void main_loop_play() {
    static unsigned long frames = 0;
    static const int probe_on = ivs_js_flag("probe");  // index.html?probe=1
    ++frames;
    if (probe_on && frames % 60 == 0) {
        char tag[32];
        snprintf(tag, sizeof(tag), "frame%lu", frames);
        em_probe_report(tag);
    }
    player->Play();
}

EMSCRIPTEN_KEEPALIVE
int main() {
#if IVS_SILENCE_STDOUT
    std::cout.rdbuf(&g_null_buf);
    std::cerr.rdbuf(&g_null_buf);
#endif
    FILE *config_file = fopen("config.xml", "w");
    size_t config_file_size = config_string.size();
    fwrite(config_string.c_str(), 1, config_file_size, config_file);
    fclose(config_file);

    if (parseRenderFromXml("config.xml", renderConfig) != RENDER_STATUS_OK) {
      // Handle error (e.g., log to console)
        std::cout << "load config error" << std::endl;
      return -1;
    }

    // Proceed with initialization
    DIR *dir = opendir(renderConfig.cachePath);
    if (!dir) {
      mkdir(renderConfig.cachePath, 0777);
    }
    std::cout << "loaded config" << std::endl;

    // Tell the local curl backend where the preloaded content lives. Every
    // segment URL is resolved against this directory by basename.
    em_local_curl_set_root(renderConfig.cachePath);
    // ?contentBase=... overrides <contentBaseUrl> from config.xml, so the content
    // source can be switched from the URL bar instead of by editing config.xml.
    char content_base[1024];
    memset_s(content_base, sizeof(content_base), 0);
    int content_base_len = ivs_js_string("contentBase", content_base, sizeof(content_base));
    if (content_base_len <= 0 &&
        (renderConfig.contentBaseUrl == NULL || renderConfig.contentBaseUrl[0] == '\0')) {
      // Nothing configured: fall back to the page's own origin. Harmless in the
      // preloaded build -- the VFS is consulted first, and the MPD prefetch
      // below finds the file already there and does nothing.
      content_base_len = ivs_default_content_base(content_base, sizeof(content_base));
    }
    const char *effective_base =
        content_base_len > 0 ? content_base : renderConfig.contentBaseUrl;
    em_local_curl_set_http_base(effective_base);

    // The MPD is read with tinyxml2::LoadFile(), not through the curl shim, so
    // when the content is served over HTTP it has to be put into the virtual
    // filesystem before the player is created. It is 113 KB; the segments stay
    // on demand. A no-op when the file is already there (preloaded build).
    if (effective_base && effective_base[0]) {
      if (em_local_curl_prefetch(renderConfig.url) != 0) {
        std::cerr << "could not obtain the MPD from '" << effective_base
                  << "'; playback will fail" << std::endl;
      }
    }
    em_local_curl_set_rate_limit((double)renderConfig.localRateLimitBytesPerSec);
    omaf_debug_set_stop_reader(ivs_js_flag("stopReader"));
    omaf_debug_set_stop_stitch(ivs_js_flag("stopStitch"));
    omaf_debug_set_stop_decode(ivs_js_flag("stopDecode"));
    omaf_debug_set_no_upload(ivs_js_flag("noUpload"));
    omaf_debug_set_no_gl(ivs_js_flag("noGL"));
    std::cout << "content root = " << renderConfig.cachePath
              << ", rate limit = " << renderConfig.localRateLimitBytesPerSec << " B/s" << std::endl;

    player->Create(renderConfig);
    RenderContext* context = InitRenderContext(renderConfig);
    if (player->Start(context) != RENDER_STATUS_OK) {
        std::cout << "start error" << std::endl;
      // Handle error
      return -1;
    }

    // Drive Player::Play() from the browser's event loop. Play() renders exactly
    // one frame per call (its internal do/while is commented out on purpose),
    // so the main loop is what makes the player tick. The old code called it
    // five times in a row and returned, which looked like "it runs but nothing
    // happens".
    emscripten_set_main_loop(main_loop_play, 0, 1);
  return 0;
}
#endif
