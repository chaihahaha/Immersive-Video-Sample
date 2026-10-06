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
//! \file     RenderSourceFactory.cpp
//! \brief    Implement class for RenderSourceFactory.
//!


#include "RenderSourceFactory.h"
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE
#endif
#ifdef _ANDROID_OS_
#include "MediaCodecRenderSource.h"
#endif
#ifdef _LINUX_OS_
#include "SWRenderSource.h"
#include <GLFW/glfw3.h>
#endif

// Diagnostics, see em_probe_render_sources / em_probe_pending_frames below.
// Deliberately plain ints at global scope (not std::atomic, which would drag
// atomics support into this translation unit): these are counters only.
int g_render_source_count = 0;
int g_pending_frame_count = 0;

VCD_NS_BEGIN


RenderSourceFactory::RenderSourceFactory(void *window)
{
    mMapRenderSource.clear();
    share_window = window;
    m_sourceNumber = 0;
    m_sourceResolution = nullptr;
    m_projFormat = VCD::OMAF::PF_UNKNOWN;
    m_sourceMode = SourceMode_Omni;
    m_highTileCol= 0;
    m_highTileRow= 0;
}

RenderSourceFactory::~RenderSourceFactory()
{
    RemoveAll();
    // RemoveAll() only queues the releases; run them so the objects are not
    // leaked at shutdown.
    PumpMainThread();
}

FrameHandler* RenderSourceFactory::CreateHandler(uint32_t video_id, uint32_t tex_id)
{
    // NOTE: this runs on the OMAF reader thread (DashMediaSource::Run ->
    // DecoderManager::CreateVideoDecoder). Under Emscripten there is exactly one
    // WebGL context and it belongs to the browser main thread, so the previous
    // glfwMakeContextCurrent(share_window) "share context in multiple thread"
    // was a no-op and the following GL calls crashed the worker. SWRenderSource
    // is now GL-free at construction; PumpMainThread() does the GL setup.
#ifdef _LINUX_OS_
    (void)share_window;
    SWRenderSource* rs = new SWRenderSource();
#endif
#ifdef _ANDROID_OS_
    MediaCodecRenderSource* rs = new MediaCodecRenderSource(tex_id);
#endif
    rs->SetVideoID(video_id);
    {
        std::lock_guard<std::mutex> lock(mMapMutex);
        if (this->mMapRenderSource.find(video_id) == this->mMapRenderSource.end()) {
            g_render_source_count++;
        }
        this->mMapRenderSource[video_id] = rs;
    }

    return rs;
}

RenderStatus RenderSourceFactory::RemoveHandler(uint32_t video_id)
{
    std::lock_guard<std::mutex> lock(mMapMutex);
    auto it = mMapRenderSource.find(video_id);
    if (it == mMapRenderSource.end()) return RENDER_NOT_FOUND;

    // DestroyRenderSource() issues GL deletes, so it has to happen on the main
    // thread; hand the object over to PumpMainThread() instead of deleting here.
    mPendingDestroy.push_back(it->second);
    mMapRenderSource.erase(it);
    g_render_source_count--;
    return RENDER_STATUS_OK;
}

RenderStatus RenderSourceFactory::RemoveAll()
{
    std::lock_guard<std::mutex> lock(mMapMutex);
    for (auto it = mMapRenderSource.begin(); it != mMapRenderSource.end(); ++it) {
        mPendingDestroy.push_back(it->second);
    }
    mMapRenderSource.clear();
    return RENDER_STATUS_OK;
}

// Diagnostics: how many render sources are alive and how many pending frame
// uploads they are each holding. One render source is created per OMAF video id
// (i.e. per selected tile), so a growing count means they are not being
// released, and each queued frame is a full tile-sized buffer.
extern "C" EMSCRIPTEN_KEEPALIVE int em_probe_render_sources(void) {
  return static_cast<int>(g_render_source_count);
}

extern "C" EMSCRIPTEN_KEEPALIVE int em_probe_pending_frames(void) {
  return static_cast<int>(g_pending_frame_count);
}

// Runs on the browser main thread. Drains the GL work queued by the reader
// thread: render source setup, frame uploads, and deferred destruction.
RenderStatus RenderSourceFactory::PumpMainThread()
{
    std::map<uint32_t, RenderSource*> snapshot;
    std::list<RenderSource*> toDestroy;
    {
        std::lock_guard<std::mutex> lock(mMapMutex);
        snapshot = mMapRenderSource;
        toDestroy.swap(mPendingDestroy);
    }

    for (auto it = toDestroy.begin(); it != toDestroy.end(); ++it) {
        RenderSource* rs = *it;
        if (rs == NULL) continue;
        rs->DestroyRenderSource();
        SAFE_DELETE(rs);
    }

    for (auto it = snapshot.begin(); it != snapshot.end(); ++it) {
        SWRenderSource* rs = dynamic_cast<SWRenderSource*>(it->second);
        if (rs != NULL) {
            rs->PumpGL();
        }
    }
    return RENDER_STATUS_OK;
}

VCD_NS_END