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
//! \file     SWRenderSource.cpp
//! \brief    Implement class for SWRenderSource.
//!

#ifdef _LINUX_OS_

#include "SWRenderSource.h"
#include <chrono>
#include "../Mesh/Render2TextureMesh.h"
#include "../Render/ShaderString.h"

// Defined in RenderSourceFactory.cpp; see em_probe_pending_frames there.

// Diagnostic switch, defined in RenderSourceFactory.cpp.
int g_debug_no_upload = 0;
extern "C" void omaf_debug_set_no_upload(int v) { g_debug_no_upload = v; }
// Keeps the per-frame copy but skips the GL upload, to separate "copy + queue"
// from "the upload itself".
int g_debug_no_gl = 0;
extern "C" void omaf_debug_set_no_gl(int v) { g_debug_no_gl = v; }

// Diagnostic counters for the frame hand-off. If queued != dropped + drained the
// queue bookkeeping is wrong; if they match, the memory is not held by the queue.
long g_proc_calls = 0;
long g_queued_total = 0;
long g_dropped_total = 0;
long g_drained_total = 0;
long g_uploads_total = 0;
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#define PROBE_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define PROBE_EXPORT
#endif
extern "C" PROBE_EXPORT long em_probe_proc_calls(void) { return g_proc_calls; }
extern "C" PROBE_EXPORT long em_probe_queued_total(void) { return g_queued_total; }
extern "C" PROBE_EXPORT long em_probe_dropped_total(void) { return g_dropped_total; }
extern "C" PROBE_EXPORT long em_probe_drained_total(void) { return g_drained_total; }
extern "C" PROBE_EXPORT long em_probe_uploads_total(void) { return g_uploads_total; }
// How many PendingFrame objects are alive right now. If this stays at 0..2 but
// the heap keeps growing, their vectors are not what is holding the memory.
long g_pending_frames_live = 0;
extern "C" PROBE_EXPORT long em_probe_pending_frames_live(void) { return g_pending_frames_live; }

VCD_NS_BEGIN

SWRenderSource::SWRenderSource()
{
    bInited = false;
    m_glReady = false;
    m_pendingResize = false;
    m_pendingPixFmt = PixelFormat::PIX_FMT_YUV420P;
    m_pendingWidth = 0;
    m_pendingHeight = 0;
    m_hasPendingFrame = false;
    m_pendingFrameW = 0;
    m_pendingFrameH = 0;
    m_pendingFrameFormat = PixelFormat::INVALID;
    m_pendingFramePts = 0;
    m_pendingFrameViewId = std::make_pair(-1, -1);
    for (int i = 0; i < 4; i++) m_pendingFrameStride[i] = 0;

    // Deliberately no GL here. This object is created on the OMAF reader thread
    // (DashMediaSource::Run -> DecoderManager::CreateVideoDecoder ->
    // RenderSourceFactory::CreateHandler), which has no GL context in the wasm
    // build. The shader, quad mesh, textures and FBO are all built later by
    // EnsureGL() on the browser main thread.
    //
    // The original code tried to work around this in RenderSourceFactory with
    // glfwMakeContextCurrent(share_window) // "share context in multiple
    // thread". Under Emscripten that is a no-op: there is exactly one WebGL
    // context and it belongs to the main thread.
}

SWRenderSource::~SWRenderSource()
{
    DestroyRenderSource();

    if (m_meshOfR2T)
    {
        delete m_meshOfR2T;
        m_meshOfR2T = NULL;
    }
}

// Records the geometry/format the source should have. Every GL call that used
// to live in this function now happens in EnsureGL(), on the main thread.
RenderStatus SWRenderSource::Initialize( int32_t pix_fmt, int32_t width, int32_t height )
{
    m_pendingPixFmt = pix_fmt;
    m_pendingWidth = width;
    m_pendingHeight = height;
    m_pendingResize = true;
    return RENDER_STATUS_OK;
}

// The original body of Initialize(pix_fmt, width, height); must run on the
// GL-owning thread.
RenderStatus SWRenderSource::EnsureGL()
{
    if (!m_glReady) {
        //1.render to texture : vertex and texCoords assign
        m_videoShaderOfR2T.Init(shader_r2t_vs, shader_r2t_fs);
        m_meshOfR2T = new Render2TextureMesh();
        m_meshOfR2T->Create();
        uint32_t vertexAttribOfR2T = m_videoShaderOfR2T.SetAttrib("vPosition");
        uint32_t texCoordsAttribOfR2T = m_videoShaderOfR2T.SetAttrib("aTexCoord");
        m_meshOfR2T->Bind( vertexAttribOfR2T, texCoordsAttribOfR2T );
        m_glReady = true;
    }

    if (!m_pendingResize) {
        return RENDER_STATUS_OK;
    }
    m_pendingResize = false;

    int32_t pix_fmt = m_pendingPixFmt;
    int32_t width = static_cast<int32_t>(m_pendingWidth);
    int32_t height = static_cast<int32_t>(m_pendingHeight);

    m_videoShaderOfR2T.Bind();
    m_videoShaderOfR2T.SetUniform1i("frameTex", 0);
    m_videoShaderOfR2T.SetUniform1i("frameU", 1);
    m_videoShaderOfR2T.SetUniform1i("frameV", 2);
    m_videoShaderOfR2T.SetUniform1i("isNV12", 0);

    uint32_t number = 0;
    switch (pix_fmt)
    {
    case PixelFormat::PIX_FMT_RGB24:
        number = 1;
        if (m_sourceWH == NULL || m_sourceWH->width == NULL || m_sourceWH->height == NULL)
        {
            if (m_sourceWH != NULL)
            {
                SAFE_DELETE_ARRAY(m_sourceWH->width);
                SAFE_DELETE_ARRAY(m_sourceWH->height);
            }
            SAFE_DELETE(m_sourceWH);
            m_sourceWH = new struct SourceWH;
            m_sourceWH->width = new uint32_t[number];
            m_sourceWH->height = new uint32_t[number];
        }
        m_sourceWH->width[0] = width;
        m_sourceWH->height[0] = height;
        break;
    case PixelFormat::PIX_FMT_YUV420P:
        number = 3;
        if (m_sourceWH == NULL || m_sourceWH->width == NULL || m_sourceWH->height == NULL)
        {
            if (m_sourceWH != NULL)
            {
                SAFE_DELETE_ARRAY(m_sourceWH->width);
                SAFE_DELETE_ARRAY(m_sourceWH->height);
            }
            SAFE_DELETE(m_sourceWH);
            m_sourceWH = new struct SourceWH;
            m_sourceWH->width = new uint32_t[number];
            m_sourceWH->height = new uint32_t[number];
        }
        m_sourceWH->width[0] = width;
        m_sourceWH->width[1] = m_sourceWH->width[0] / 2;
        m_sourceWH->width[2] = m_sourceWH->width[1];
        m_sourceWH->height[0] = height;
        m_sourceWH->height[1] = m_sourceWH->height[0] / 2;
        m_sourceWH->height[2] = m_sourceWH->height[1];
        break;
    default:
        break;
    }
    SetSourceTextureNumber(number);
    CreateRenderSource(bInited);
    bInited = true;
    return RENDER_STATUS_OK;
}

RenderStatus SWRenderSource::Initialize(struct MediaSourceInfo *mediaSourceInfo)
{
    if (NULL == mediaSourceInfo)
    {
        return RENDER_ERROR;
    }
    // Only these three fields were ever used; deferring through the scalar
    // overload keeps all GL work on the main thread.
    return Initialize(static_cast<int32_t>(mediaSourceInfo->pixFormat),
                      static_cast<int32_t>(mediaSourceInfo->width),
                      static_cast<int32_t>(mediaSourceInfo->height));
}

RenderStatus SWRenderSource::CreateRenderSource(bool hasInited)
{
    if (CreateSourceTex() != RENDER_STATUS_OK || CreateR2TFBO(hasInited) != RENDER_STATUS_OK)
    {
        return RENDER_ERROR;
    }
    return RENDER_STATUS_OK;
}

RenderStatus SWRenderSource::CreateSourceTex()
{
    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    //1. initial r2t three textures.
    uint32_t sourceTextureNumber = GetSourceTextureNumber();
    if (m_sourceTextureHandle == NULL)
    {
        m_sourceTextureHandle = new uint32_t[sourceTextureNumber];
        renderBackend->GenTextures(sourceTextureNumber, m_sourceTextureHandle);
    }
    for (uint32_t i = 0; i < sourceTextureNumber; i++)
    {
        if (i == 0)
            renderBackend->ActiveTexture(GL_TEXTURE0);
        else if (i == 1)
            renderBackend->ActiveTexture(GL_TEXTURE1);
        else if (i == 2)
            renderBackend->ActiveTexture(GL_TEXTURE2);
        else if (i == 3)
            renderBackend->ActiveTexture(GL_TEXTURE3);

        renderBackend->BindTexture(GL_TEXTURE_2D, m_sourceTextureHandle[i]);
        struct SourceWH *sourceWH = GetSourceWH();

        renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

        renderBackend->TexImage2D(GL_TEXTURE_2D, 0, GL_R8, sourceWH->width[i], sourceWH->height[i], 0, GL_RED, GL_UNSIGNED_BYTE, NULL);
    }
    return RENDER_STATUS_OK;
}

RenderStatus SWRenderSource::CreateR2TFBO(bool hasInited)
{
    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    //2.initial FBOs
    if (!hasInited)
    {
        renderBackend->GenTextures(1, &m_textureOfR2T);
    }
    renderBackend->BindTexture(GL_TEXTURE_2D, m_textureOfR2T);
    struct SourceWH *sourceWH = GetSourceWH();

    renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
    renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    renderBackend->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);

    renderBackend->TexImage2D(GL_TEXTURE_2D, 0, GL_RGB, sourceWH->width[0], sourceWH->height[0], 0, GL_RGB, GL_UNSIGNED_BYTE, NULL);

    if (!hasInited)
    {
        renderBackend->GenFramebuffers(1, &m_fboR2THandle);
    }
    renderBackend->BindFramebuffer(GL_FRAMEBUFFER, m_fboR2THandle);
    renderBackend->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, m_textureOfR2T, 0);

    if (renderBackend->CheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
    {
        LOG(ERROR)<<"Video "<< GetVideoID() <<": glCheckFramebufferStatus not complete when CreateR2TFBO"<<std::endl;
        return RENDER_ERROR;
    }
    else
    {
        LOG(INFO)<<"Video "<< GetVideoID() <<": glCheckFramebufferStatus complete when CreateR2TFBO"<<std::endl;
    }
    return RENDER_STATUS_OK;
}

RenderStatus SWRenderSource::UpdateR2T(BufferInfo* bufInfo)
{
    std::chrono::high_resolution_clock clock;
    uint64_t start1 = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    //1. update source texture
    uint32_t sourceTextureNumber = GetSourceTextureNumber();
    uint32_t *sourceTextureHandle = GetSourceTextureHandle();
    struct SourceWH *sourceWH = GetSourceWH();
    for (uint32_t i = 0; i < sourceTextureNumber; i++)
    {
        if (i == 0)
            renderBackend->ActiveTexture(GL_TEXTURE0);
        else if (i == 1)
            renderBackend->ActiveTexture(GL_TEXTURE1);
        else if (i == 2)
            renderBackend->ActiveTexture(GL_TEXTURE2);
        else if (i == 3)
            renderBackend->ActiveTexture(GL_TEXTURE3);
        renderBackend->BindTexture(GL_TEXTURE_2D, sourceTextureHandle[i]);
        if (bufInfo->stride[i] == 0)
        {
            LOG(ERROR) << "i " << i << "buf stride is zero! PTS " << bufInfo->pts << " video id " << m_VideoID << endl;
            return RENDER_ERROR;
        }
        renderBackend->PixelStorei(GL_UNPACK_ROW_LENGTH, bufInfo->stride[i]);
        LOG(INFO) <<" i = " << i << " TexSubImage2D width " << sourceWH->width[i] << " height " << sourceWH->height[i] << " video id " << m_VideoID << " PTS " << bufInfo->pts << endl;
        if (GetSourceTextureNumber() == 1)
            renderBackend->TexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, sourceWH->width[i], sourceWH->height[i], GL_RGB, GL_UNSIGNED_BYTE, bufInfo->buffer[i]); //use rgb data
        else
            renderBackend->TexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, sourceWH->width[i], sourceWH->height[i], GL_RED, GL_UNSIGNED_BYTE, bufInfo->buffer[i]); //use yuv data
    }
    uint64_t end1 = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
    LOG(INFO)<<"update process is:"<<(end1 - start1)<<endl;
    //2. bind source texture and r2tFBO
    uint64_t start2 = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
    uint32_t fboR2THandle = GetFboR2THandle();
    renderBackend->BindFramebuffer(GL_FRAMEBUFFER, fboR2THandle);

    m_videoShaderOfR2T.Bind();
    renderBackend->BindVertexArray(this->m_meshOfR2T->GetVAOHandle()); // check
    for (uint32_t i = 0; i < sourceTextureNumber; i++)
    {
        if (i == 0)
            renderBackend->ActiveTexture(GL_TEXTURE0);
        else if (i == 1)
            renderBackend->ActiveTexture(GL_TEXTURE1);
        else if (i == 2)
            renderBackend->ActiveTexture(GL_TEXTURE2);
        else if (i == 3)
            renderBackend->ActiveTexture(GL_TEXTURE3);
        renderBackend->BindTexture(GL_TEXTURE_2D, sourceTextureHandle[i]);
    }
    renderBackend->Viewport(0, 0, sourceWH->width[0], sourceWH->height[0]);
    renderBackend->DrawArrays(GL_TRIANGLE_STRIP, 0, 6);
    uint64_t end2 = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
    LOG(INFO)<<"bind process is:"<<(end2 - start2)<<endl;
    return RENDER_STATUS_OK;
}

RenderStatus SWRenderSource::DestroyRenderSource()
{
    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    uint32_t textureOfR2T = GetTextureOfR2T();
    if (textureOfR2T)
    {
        renderBackend->DeleteTextures(1, &textureOfR2T);
    }
    uint32_t sourceTextureNumber = GetSourceTextureNumber();
    uint32_t *sourceTextureHandle = GetSourceTextureHandle();
    if (sourceTextureHandle)
    {
        renderBackend->DeleteTextures(sourceTextureNumber, sourceTextureHandle);
    }
    uint32_t fboR2THandle = GetFboR2THandle();
    if (fboR2THandle)
    {
        renderBackend->DeleteFramebuffers(1, &fboR2THandle);
    }
    return RENDER_STATUS_OK;
}

// Runs on the decoder/reader thread. Everything here is CPU-only: the GL upload
// happens later in PumpGL(), on the browser main thread.
RenderStatus SWRenderSource::process(BufferInfo* bufInfo)
{
    if (bufInfo == nullptr) return RENDER_NULL_HANDLE;
    m_viewID = bufInfo->view_id;

    if (bufInfo->width == 0 || bufInfo->height == 0) return RENDER_ERROR;

    if (bufInfo->bFormatChange || !bInited) {
        m_pendingPixFmt = bufInfo->pixelFormat;
        m_pendingWidth = bufInfo->width;
        m_pendingHeight = bufInfo->height;
        m_pendingResize = true;
        LOG(INFO) << "PTS " << bufInfo->pts << " texture need to resize to "
                  << bufInfo->width << " x " << bufInfo->height << endl;
    }

    // The region description is pure data, so it can be copied here.
    RegionData* curData = new RegionData(bufInfo->regionInfo->GetRegionWisePacking(), bufInfo->regionInfo->GetSourceInRegion(), bufInfo->regionInfo->GetSourceInfo());
    mCurRegionInfo.push_back(curData);

    // Defensive bounds. A decoder that produced a garbage stride (the logs do
    // contain "avcodec_receive_frame FAILED") would otherwise make the copy
    // below request an enormous allocation, which is fatal with exceptions
    // disabled (-fignore-exceptions) and can exhaust the wasm heap.
    static const uint32_t kMaxDimension = 16384;
    static const size_t kMaxPlaneBytes = 64u * 1024u * 1024u;
    if (bufInfo->width > kMaxDimension || bufInfo->height > kMaxDimension) {
        LOG(ERROR) << "Video " << GetVideoID() << ": implausible frame size "
                   << bufInfo->width << "x" << bufInfo->height << ", dropping" << std::endl;
        return RENDER_ERROR;
    }

    // Diagnostic switch (set from the page): skip the per-frame copy entirely,
    // to test whether the remaining heap growth comes from this hand-off or from
    // somewhere else. See omaf_debug_set_no_upload below.
    if (g_debug_no_upload) return RENDER_STATUS_OK;

    // The decoder frees its AVFrame (which owns bufInfo->buffer[i]) as soon as
    // this returns, so the pixels have to be copied out now -- into the reusable
    // staging buffers, which are resized in place and therefore do not allocate
    // per frame.
    g_proc_calls++;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);

        // Only the newest frame is ever drawn, and the decoder thread runs well
        // ahead of the main render loop, so drop this frame if the previous one
        // has not been uploaded yet.
        if (m_hasPendingFrame) {
            g_dropped_total++;
            return RENDER_STATUS_OK;
        }

        m_pendingFrameW = bufInfo->width;
        m_pendingFrameH = bufInfo->height;
        m_pendingFrameFormat = bufInfo->pixelFormat;
        m_pendingFramePts = bufInfo->pts;
        m_pendingFrameViewId = bufInfo->view_id;

        uint32_t planeNumber = (bufInfo->pixelFormat == PixelFormat::PIX_FMT_RGB24) ? 1 : 3;
        for (uint32_t i = 0; i < planeNumber && i < 4; i++) {
            uint32_t planeHeight = (i == 0) ? bufInfo->height : (bufInfo->height / 2);
            size_t bytes = static_cast<size_t>(bufInfo->stride[i]) * planeHeight;
            if (bytes > kMaxPlaneBytes) {
                LOG(ERROR) << "Video " << GetVideoID() << ": plane " << i << " copy size "
                           << bytes << " bytes exceeds the limit, dropping frame" << std::endl;
                return RENDER_ERROR;
            }
            m_pendingFrameStride[i] = bufInfo->stride[i];
            if (bufInfo->buffer[i] == nullptr || bytes == 0) {
                m_uploadPlanes[i].clear();
                continue;
            }
            if (m_uploadPlanes[i].size() != bytes) {
                m_uploadPlanes[i].resize(bytes);
            }
            memcpy(m_uploadPlanes[i].data(), bufInfo->buffer[i], bytes);
        }
        m_hasPendingFrame = true;
        g_queued_total++;
    }

    return RENDER_STATUS_OK;
}

// Runs on the browser main thread only.
RenderStatus SWRenderSource::PumpGL()
{
    RenderStatus ret = EnsureGL();
    if (ret != RENDER_STATUS_OK) {
        return ret;
    }

    // Hold the lock across the upload: the staging buffers are shared, so the
    // decoder thread must not start overwriting them while GL is reading them.
    // That also provides the backpressure the pipeline needs.
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    if (!m_hasPendingFrame) {
        return RENDER_STATUS_OK;
    }
    m_hasPendingFrame = false;
    g_drained_total++;
    if (!bInited) {
        return RENDER_STATUS_OK;  // geometry not applied yet; drop rather than crash
    }

    BufferInfo bi;
    memset(&bi, 0, sizeof(BufferInfo));
    bi.width = m_pendingFrameW;
    bi.height = m_pendingFrameH;
    bi.pixelFormat = m_pendingFrameFormat;
    bi.pts = m_pendingFramePts;
    bi.view_id = m_pendingFrameViewId;
    bi.regionInfo = nullptr;  // already captured in mCurRegionInfo
    for (size_t i = 0; i < 4; i++) {
        bi.stride[i] = m_pendingFrameStride[i];
        bi.buffer[i] = m_uploadPlanes[i].empty() ? nullptr : m_uploadPlanes[i].data();
    }

    if (g_debug_no_gl) return RENDER_STATUS_OK;  // copy was made, upload skipped
    g_uploads_total++;
    ret = UpdateR2T(&bi);
    if (RENDER_STATUS_OK != ret) {
        LOG(ERROR) << "Video " << GetVideoID() << ": UpdateR2T failed" << std::endl;
    }
    return ret;
}

VCD_NS_END
#endif