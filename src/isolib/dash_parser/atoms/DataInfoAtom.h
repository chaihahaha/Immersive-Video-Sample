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
//! \file:   DataInfoAtom.h
//! \brief:  Data Information Atom class
//! \detail: 'dinf' Atom implementation.
//!
//! Created on October 15, 2019, 13:39 PM
//!

#ifndef _DATAINFORMATIONATOM_H_
#define _DATAINFORMATIONATOM_H_

#include "Atom.h"
#include "Stream.h"
#include "FormAllocator.h"
#include "DataRefAtom.h"

VCD_MP4_BEGIN

class DataInformationAtom : public Atom
{
public:

    //!
    //! \brief Constructor
    //!
    DataInformationAtom();

    //!
    //! \brief Destructor
    //!
    virtual ~DataInformationAtom() = default;

    //!
    //! \brief    Add Data Entry Atom
    //!
    //! \param    [in] std::shared_ptr<DataEntryAtom>
    //!           entry
    //!
    //! \return   std::uint16_t
    //!           data entry size
    //!
    std::uint16_t AddDataEntryAtom(std::shared_ptr<DataEntryAtom> dataEntryAtom);

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
    DataReferenceAtom m_dataReferenceAtom;  //!< Data Reference Atom
};

VCD_MP4_END;
#endif /* _DATAINFORMATIONATOM_H_ */
