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
//! \file     RenderContext.h
//! \brief    Defines class for RenderContext.
//!
#ifndef _RenderContext_H_
#define _RenderContext_H_

#include "../Common/Common.h"
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#ifdef _LINUX_OS_
#include <glm/glm.hpp>
#include <glm/gtc/matrix_transform.hpp>
#include <glm/gtc/type_ptr.hpp>
#endif
VCD_NS_BEGIN

class RenderContext
{
public:
    RenderContext(){
         m_renderContextType = DEFAULT_CONTEXT;
         // Initial horizontal angle : toward -Z
         m_horizontalAngle   = 0.0f;
         // Initial vertical angle : none
         m_verticalAngle     = 0.0f;
         // Initial Field of View
         m_speed             = 0.005f; // 3 units / second
         m_mouseSpeed        = 0.005f;
         m_lastCursorX       = 0.0;
         m_lastCursorY       = 0.0;
         m_hasLastCursor     = false;
         m_window            = NULL;
         m_windowWidth       = 0;
         m_windowHeight      = 0;
         m_hFOV              = 0;
         m_vFOV              = 0;
         m_projFormat        = VCD::OMAF::PF_UNKNOWN;
         m_row               = 0;
         m_col               = 0;
         m_renderInterval    = 0;
         m_sourceMode        = Source_Mode::SourceMode_Omni;
    };

    virtual ~RenderContext()=default;

    //! \brief Cursor movement since the previous frame, in pixels.
    //!
    //! Call once per frame, before using the result. Returns 0 on the first call
    //! and on the first frame after the button was released, so that starting a
    //! new drag does not make the view jump.
    //!
    //! \param  [in] xpos, ypos
    //!         cursor position as returned by glfwGetCursorPos()
    //!         [out] dx, dy
    //!         movement since the previous call, in pixels
    //!
    void ConsumeCursorDelta(double xpos, double ypos, double *dx, double *dy)
    {
        if (!m_hasLastCursor)
        {
            m_lastCursorX = xpos;
            m_lastCursorY = ypos;
            m_hasLastCursor = true;
        }
        *dx = xpos - m_lastCursorX;
        *dy = ypos - m_lastCursorY;
        m_lastCursorX = xpos;
        m_lastCursorY = ypos;
    }

    //! \brief Forget the previous cursor position.
    //!
    //! Call while the drag button is released, so the next drag starts from a
    //! fresh reference and the first frame of that drag reports no movement.
    //!
    void ResetCursorDelta()
    {
        m_hasLastCursor = false;
    }

    //! \brief swap buffer
    //!
    //! \param  [in] window
    //          window handle
    //!         [in] param
    //!         parameter for the swap buffer
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus SwapBuffers(void * window, int param) = 0;

    //! \brief get pose and status according to inputs
    //!
    //! \param  [out] HeadPose
    //          current pose
    //!         [out] status
    //!         player status
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual RenderStatus GetStatusAndPose(HeadPose *pose, uint32_t* status) = 0;

    //! \brief initialize render context
    //!
    //! \return RenderStatus
    //!         RENDER_STATUS_OK if success, else fail reason
    //!
    virtual void* InitContext() = 0;

    //! \brief get window handle
    //!
    //! \return void *
    //!         m_window handle
    //!
    void *GetWindow() {return m_window;}

    //! \brief Set projection format for setting up view/projection model for 3D/2D
    //!
    //! \param  [in] int32_t
    //          projection format
    //!
    void SetProjectionFormat(int32_t projFormat) { m_projFormat = projFormat; };

    //! \brief Set source mode for setting up event for 3D/2D
    //!
    //! \param  [in] int32_t
    //          source mode
    //!
    void SetSourceMode(int32_t sourceMode) { m_sourceMode = sourceMode; };

    //! \brief check whether the render is running
    //!
    //! \return bool
    //!         isrunning or not
    //!
    virtual bool isRunning() = 0;

    //! \brief Set full resolution for calculating zoomFactor.
    //!
    //! \param  [in] uint32_t
    //          full picture width
    //!         [out] uint32_t
    //!         full picture height
    //!
    virtual void SetFullResolution(uint32_t width, uint32_t height) { return; };
    //! \brief Set Row And Col Information of stream in high quality
    //!
    //! \param  [in] uint32_t
    //          row
    //!         [out] uint32_t
    //!         col
    //!
    void SetRowAndColInfo(uint32_t row, uint32_t col) { m_row = row; m_col = col; };
    //! \brief Set render interval of rendering
    //!
    //! \param  [in] uint32_t
    //          render interval(ms)
    //!
    void SetRenderInterval(uint32_t interval) { m_renderInterval = interval; };

#ifdef _LINUX_OS_
    //! \brief get render projection matrix
    //!
    //! \return glm::mat4
    //!         render projection matrix
    //!
    glm::mat4 GetProjectionMatrix() {return m_projectionMatrix;}

    //! \brief get render view model matrix
    //!
    //! \return glm::mat4
    //!         render view model matrix
    //!
    glm::mat4 GetViewModelMatrix() {return m_viewModelMatrix;}
#endif
protected:
    enum RenderContextType  m_renderContextType;
    void                   *m_window;
    uint32_t                m_windowWidth;
    uint32_t                m_windowHeight;
    float                   m_hFOV;
    float                   m_vFOV;
#ifdef _LINUX_OS_
    glm::mat4               m_projectionMatrix;
    glm::mat4               m_viewModelMatrix;
#endif
    float                   m_horizontalAngle; //! Initial horizontal angle : toward -Z

    float                   m_verticalAngle; //! Initial vertical angle : none

    float                   m_speed; // 3 units / second
    float                   m_mouseSpeed;

    // Cursor position sampled on the previous frame.
    //
    // The look-around code used to compute the drag delta as
    // (windowCentre - cursorPos), relying on glfwSetCursorPos() to warp the
    // cursor back to the centre after every frame. That works with a desktop
    // GLFW, where warping is real. In the browser it is not: Emscripten's
    // glfwSetCursorPos() is an empty function ("I believe it is not possible to
    // move the mouse with javascript") and glfwGetCursorPos() returns the raw
    // DOM cursor, which under pointer lock is accumulated with
    // Browser.mouseX += Browser.mouseMovementX and never reset. The delta
    // therefore grew with every pixel dragged -- the further you moved from the
    // centre, the faster the view spun, once per frame.
    //
    // These members let the rotation use the real per-frame movement instead,
    // which is what the old centre-relative delta emulated on the desktop.
    double                  m_lastCursorX;
    double                  m_lastCursorY;
    bool                    m_hasLastCursor;

    int32_t                 m_projFormat;    //<! projection format for setting up view/projection model for 3D/2D

    int32_t                 m_sourceMode;    //<! source mode for setting up event for 3D/2D

    uint32_t                m_row; //<! highest quality ranking stream row. utilized to determine the max speed of motion.
    uint32_t                m_col; //<! highest quality ranking stream col. utilized to determine the max speed of motion.
    uint32_t                m_renderInterval; //<! render interval
};

VCD_NS_END
#endif /* _RenderContext_H_ */
