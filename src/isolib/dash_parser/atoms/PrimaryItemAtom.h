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
 */

//!
//! \file:   PrimaryItemAtom.h
//! \brief:  Primary Item Atom class
//! \detail: 'pitm' Atom
//!
//! Created on October 16, 2019, 13:39 PM
//!

#ifndef _PRIMARYITEMATOM_H_
#define _PRIMARYITEMATOM_H_

#include "FormAllocator.h"
#include "FullAtom.h"

VCD_MP4_BEGIN

class PrimaryItemAtom : public FullAtom
{
public:

    //!
    //! \brief Constructor
    //!
    PrimaryItemAtom();

    //!
    //! \brief Destructor
    //!
    virtual ~PrimaryItemAtom() = default;

    //!
    //! \brief    Set Item Id
    //!
    //! \param    [in] std::uint32_t
    //!           Item Id value
    //!
    //! \return   void
    //!
    void SetItemId(std::uint32_t itemId);

    //!
    //! \brief    Get Item Id
    //!
    //! \return   std::uint32_t
    //!           Item Id
    //!
    std::uint32_t GetItemId() const;

    //!
    //! \brief    Write atom information to stream
    //!
    //! \param    [in,out] Stream&
    //!           bitstream that contains atom information
    //!
    //! \return   void
    //!
    virtual void ToStream(Stream& str) override;

    //!
    //! \brief    Parse atom information from stream
    //!
    //! \param    [in,out] Stream&
    //!           bitstream that contains atom information
    //!
    //! \return   void
    //!
    virtual void FromStream(Stream& str) override;

private:
    std::uint32_t m_itemId;  //!< The identifier of the primary item
};

VCD_MP4_END;
#endif /* _PRIMARYITEMATOM_H_ */
