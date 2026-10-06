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
//! \file     SWRenderSource.h
//! \brief    Defines class for SWRenderSource.
//!

#ifdef _LINUX_OS_

#ifndef _SWRENDERSOURCE_H_
#define _SWRENDERSOURCE_H_

#include <vector>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>
#include "../Common/Common.h"
#include "RenderSource.h"

// Diagnostics (see omaf_debug_set_* in render.cpp).
extern int g_debug_no_upload;
extern int g_debug_no_gl;
#include "../Render/RenderBackend.h"


VCD_NS_BEGIN

class SWRenderSource
    : public RenderSource
{
public:
    SWRenderSource();
    virtual ~SWRenderSource();
    //! \brief Initialize RenderSource data according to mediaSource Info
    //!
    //! \param  [in] struct MediaSourceInfo *
    //!         Media Source Info
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus Initialize(struct MediaSourceInfo *mediaSourceInfo);
    virtual RenderStatus Initialize( int32_t pix_fmt, int32_t width, int32_t height );

    //! \brief Update the render source
    //!
    //! \param  [in] BufferInfo*
    //!         frame buffer info
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus UpdateR2T(BufferInfo* bufInfo);
    //! \brief Destroy the render source
    //!
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus DestroyRenderSource();

    //! \brief Create a render source
    //!
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus CreateRenderSource(bool hasInited);

    //! \brief Queue a decoded frame for upload. Runs on the decoder/reader
    //!        thread and performs no GL work: the pixel planes are copied out
    //!        of the decoder's AVFrame (which the caller frees as soon as this
    //!        returns) and uploaded later by PumpGL().
    virtual RenderStatus process(BufferInfo* bufInfo);

    //! \brief Do all pending GL work: build shader/mesh/textures on first use,
    //!        then upload every queued frame.
    //!
    //! MUST only be called from the thread that owns the GL context -- in the
    //! wasm build that is the browser main thread, via
    //! RenderSourceFactory::PumpMainThread().
    RenderStatus PumpGL();

private:

    //! \brief Compile shader / build mesh / create textures and FBO, once.
    RenderStatus EnsureGL();

    // Reusable upload staging, one set per render source.
    //
    // The frame handed over by the decoder thread must be copied, because the
    // decoder frees its AVFrame as soon as process() returns. Doing that with a
    // fresh std::vector per frame allocated (and, in practice, retained)
    // 1-4 MB per frame, which exhausted the wasm heap after ~90 s of playback.
    // Resizing these buffers in place allocates only on the first frame and
    // whenever the resolution changes.
    std::vector<uint8_t> m_uploadPlanes[4];
    bool                 m_hasPendingFrame;
    uint32_t             m_pendingFrameW;
    uint32_t             m_pendingFrameH;
    uint32_t             m_pendingFrameStride[4];
    PixelFormat::Enum    m_pendingFrameFormat;
    uint64_t             m_pendingFramePts;
    std::pair<int32_t, int32_t> m_pendingFrameViewId;


    //! \brief Create Source Texture
    //!
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    RenderStatus CreateSourceTex();
    //! \brief Create R2T FBO
    //!
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    RenderStatus CreateR2TFBO(bool hasInited);

private:
    bool            bInited;
    bool            m_glReady;
    // deferred Initialize() parameters, applied inside EnsureGL()
    bool            m_pendingResize;
    int32_t         m_pendingPixFmt;
    uint32_t        m_pendingWidth;
    uint32_t        m_pendingHeight;

    std::mutex                                 m_pendingMutex;
};

VCD_NS_END
#endif /* _RENDERSOURCE_H_ */
#endif