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
//! \file     CubeMapRender.h
//! \brief    Defines class for CubeMapRender.
//!

#ifdef _LINUX_OS_

#ifndef _CUBEMAPRENDER_H_
#define _CUBEMAPRENDER_H

#include "../Common/Common.h"
#include "SurfaceRender.h"
#include "VideoShader.h"
#include "../Mesh/CubeMapMesh.h"

VCD_NS_BEGIN

class CubeMapRender
    : public SurfaceRender
{
public:
    //! \brief Creator for the class
    //!
    //! \param  [in] RenderBackend*
    //!         RenderBackend Interface
    //!
    //! \return N/A
    //!
    CubeMapRender();

    //! \brief Destoryer for the class
    //!
    //! \param  [in]
    //!         Description
    //!
    //! \return N/A
    //!
    //!
    virtual ~CubeMapRender();

    //! \brief The render function
    //!
    //! \param  [in] RenderBackend *renderBackend
    //!         renderBackend interface
    //!         [in] uint32_t width
    //!         render width
    //!         [in] uint32_t height
    //!         render height
    //!         glm::mat4
    //!         ProjectionMatrix
    //!         glm::mat4
    //!         ViewModelMatrix
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus Render(uint32_t onScreenTexHandle, uint32_t width, uint32_t height, glm::mat4 ProjectionMatrix, glm::mat4 ViewModelMatrix);

    virtual void SetUniformFrameTex();

private:
};

VCD_NS_END
#endif /* _CUBEMAPRENDER_H_ */
#endif
