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
//! \file:   OmafPackage.cpp
//! \brief:  OmafPackage class implementation
//!
//! Created on April 30, 2019, 6:04 AM
//!

#include <dlfcn.h>
#include <math.h>

#include "OmafPackage.h"
#include "VideoStreamPluginAPI.h"
#include "AudioStreamPluginAPI.h"
#include "DefaultSegmentation.h"
#include "MultiViewSegmentation.h"

VCD_NS_BEGIN

OmafPackage::OmafPackage()
{
    m_initInfo = NULL;
    m_segmentation = NULL;
    m_extractorTrackMan = NULL;
    m_isSegmentationStarted = false;
    m_videoThreadId = 0;
    m_hasAudio = false;
    m_audioThreadId = 0;
    m_hasChunkDurCorrected = false;
    m_hasViewSEI = false;
    m_sourceMode = OMNIDIRECTIONAL_VIDEO_PACKING;
}

OmafPackage::OmafPackage(const OmafPackage& src)
{
    m_initInfo = std::move(src.m_initInfo);
    m_segmentation = std::move(src.m_segmentation);
    m_extractorTrackMan = std::move(src.m_extractorTrackMan);
    m_isSegmentationStarted = src.m_isSegmentationStarted;
    m_videoThreadId = src.m_videoThreadId;
    m_hasAudio      = src.m_hasAudio;
    m_audioThreadId = src.m_audioThreadId;
    m_hasChunkDurCorrected = src.m_hasChunkDurCorrected;
    m_hasViewSEI = src.m_hasViewSEI;
    m_sourceMode = src.m_sourceMode;
}

OmafPackage& OmafPackage::operator=(OmafPackage&& other)
{
    m_initInfo = std::move(other.m_initInfo);
    m_segmentation = std::move(other.m_segmentation);
    m_extractorTrackMan = std::move(other.m_extractorTrackMan);
    m_isSegmentationStarted = other.m_isSegmentationStarted;
    m_videoThreadId = other.m_videoThreadId;
    m_hasAudio      = other.m_hasAudio;
    m_audioThreadId = other.m_audioThreadId;
    m_hasChunkDurCorrected = other.m_hasChunkDurCorrected;
    m_hasViewSEI = other.m_hasViewSEI;
    m_sourceMode = other.m_sourceMode;

    return *this;
}

OmafPackage::~OmafPackage()
{
    if(m_videoThreadId != 0)
    {
        pthread_join(m_videoThreadId, NULL);
    }

    if(m_audioThreadId != 0)
    {
        pthread_join(m_audioThreadId, NULL);
    }

    DELETE_MEMORY(m_segmentation);
    DELETE_MEMORY(m_extractorTrackMan);

    std::map<uint8_t, MediaStream*>::iterator it;
    for (it = m_streams.begin(); it != m_streams.end();)
    {
        MediaStream *stream = it->second;
        if (stream)
        {
            CodecId codec = stream->GetCodecId();
            std::map<CodecId, void*>::iterator itHdl;
            itHdl = m_streamPlugins.find(codec);
            if (itHdl == m_streamPlugins.end())
            {
                return;
            }
            void *pluginHdl = itHdl->second;
            if (!pluginHdl)
            {
                return;
            }
            if (stream->GetMediaType() == VIDEOTYPE)
            {
                DestroyVideoStream* destroyVS = NULL;
                destroyVS = (DestroyVideoStream*)dlsym(pluginHdl, "Destroy");
                const char *dlsymErr = dlerror();
                if (dlsymErr)
                {
                    return;
                }
                if (!destroyVS)
                {
                    return;
                }
                destroyVS((VideoStream*)(stream));
            }
            else if (stream->GetMediaType() == AUDIOTYPE)
            {
                DestroyAudioStream* destroyAS = NULL;
                destroyAS = (DestroyAudioStream*)dlsym(pluginHdl, "Destroy");
                const char *dlsymErr = dlerror();
                if (dlsymErr)
                {
                    return;
                }
                if (!destroyAS)
                {
                    return;
                }
                destroyAS((AudioStream*)(stream));
            }
        }

        m_streams.erase(it++);
    }
    m_streams.clear();

    std::map<CodecId, void*>::iterator itPlug;
    for (itPlug = m_streamPlugins.begin(); itPlug != m_streamPlugins.end(); )
    {
        void *plugHdl = itPlug->second;
        if (plugHdl)
        {
            dlclose(plugHdl);
            plugHdl = NULL;
        }
        m_streamPlugins.erase(itPlug++);
    }
    m_streamPlugins.clear();
}

int32_t OmafPackage::AddMediaStream(uint8_t streamIdx, BSBuffer *bs)
{
    if (!bs || !(bs->data))
        return OMAF_ERROR_NULL_PTR;

    if (!(bs->dataSize))
        return OMAF_ERROR_DATA_SIZE;

    if (bs->mediaType == VIDEOTYPE)
    {
        if (bs->codecId == CODEC_ID_H265)
        {
            void *pluginHdl = NULL;
            std::map<CodecId, void*>::iterator it;
            it = m_streamPlugins.find(CODEC_ID_H265);
            if (it == m_streamPlugins.end())
            {
                char hevcPluginName[1024] = { 0 };//"/usr/local/lib/libHevcVideoStreamProcess.so";
                uint32_t videoPluginPathLen = strlen(m_initInfo->videoProcessPluginPath);
                if (m_initInfo->videoProcessPluginPath[videoPluginPathLen - 1] == '/')
                {
                    snprintf(hevcPluginName, 1024, "%slib%s.so", m_initInfo->videoProcessPluginPath, m_initInfo->videoProcessPluginName);
                }
                else
                {
                    snprintf(hevcPluginName, 1024, "%s/lib%s.so", m_initInfo->videoProcessPluginPath, m_initInfo->videoProcessPluginName);
                }

                pluginHdl = dlopen(hevcPluginName, RTLD_LAZY);
                const char *dlsymErr = dlerror();
                if (!pluginHdl)
                {
                    if (dlsymErr)
                    {
                    }
                    return OMAF_ERROR_DLOPEN;
                }
                m_streamPlugins.insert(std::make_pair(CODEC_ID_H265, pluginHdl));
            }
            else
            {
                pluginHdl = it->second;
                if (!pluginHdl)
                {
                    return OMAF_ERROR_NULL_PTR;
                }
            }

            CreateVideoStream* createVS = NULL;
            createVS = (CreateVideoStream*)dlsym(pluginHdl, "Create");
            const char* dlsymErr1 = dlerror();
            if (dlsymErr1)
            {
                return OMAF_ERROR_DLSYM;
            }

            if (!createVS)
            {
                return OMAF_ERROR_NULL_PTR;
            }

            VideoStream *vs = createVS();
            if (!vs)
            {
                return OMAF_ERROR_NULL_PTR;
            }

            ((MediaStream*)vs)->SetMediaType(VIDEOTYPE);
            ((MediaStream*)vs)->SetCodecId(CODEC_ID_H265);

            m_streams.insert(std::make_pair(streamIdx, (MediaStream*)vs));
            int32_t ret = vs->Initialize(streamIdx, bs, m_initInfo);
            if (ret)
            {
                return ret;
            }

            if (vs->GetNovelViewSEIInfo())
            {
                m_hasViewSEI = true;
            }

            if (!(vs->GetTileInRow()) || !(vs->GetTileInCol()))
            {
                if (m_initInfo->segmentationInfo->splitTile)
                {
                    m_initInfo->segmentationInfo->splitTile = 0;
                }
            }
            vs = NULL;
        }
        else
        {
            return OMAF_ERROR_INVALID_CODEC;
        }
    } else if (bs->mediaType == AUDIOTYPE) {
        m_hasAudio = true;
        if (bs->codecId == CODEC_ID_AAC)
        {
            void *pluginHdl = NULL;
            std::map<CodecId, void*>::iterator it;
            it = m_streamPlugins.find(CODEC_ID_AAC);
            if (it == m_streamPlugins.end())
            {
                char aacPluginName[1024] = { 0 };//"/usr/local/lib/libAACAudioStreamProcess.so";
                uint32_t audioPluginPathLen = strlen(m_initInfo->audioProcessPluginPath);
                if (m_initInfo->audioProcessPluginPath[audioPluginPathLen - 1] == '/')
                {
                    snprintf(aacPluginName, 1024, "%slib%s.so", m_initInfo->audioProcessPluginPath, m_initInfo->audioProcessPluginName);
                }
                else
                {
                    snprintf(aacPluginName, 1024, "%s/lib%s.so", m_initInfo->audioProcessPluginPath, m_initInfo->audioProcessPluginName);
                }

                pluginHdl = dlopen(aacPluginName, RTLD_LAZY);
                const char *dlsymErr = dlerror();
                if (!pluginHdl)
                {
                    if (dlsymErr)
                    {
                    }
                    return OMAF_ERROR_DLOPEN;
                }
                m_streamPlugins.insert(std::make_pair(CODEC_ID_AAC, pluginHdl));
            }
            else
            {
                pluginHdl = it->second;
                if (!pluginHdl)
                {
                    return OMAF_ERROR_NULL_PTR;
                }
            }

            CreateAudioStream* createAS = NULL;
            createAS = (CreateAudioStream*)dlsym(pluginHdl, "Create");
            const char* dlsymErr1 = dlerror();
            if (dlsymErr1)
            {
                return OMAF_ERROR_DLSYM;
            }

            if (!createAS)
            {
                return OMAF_ERROR_NULL_PTR;
            }

            AudioStream *as = createAS();
            if (!as)
            {
                return OMAF_ERROR_NULL_PTR;
            }

            ((MediaStream*)as)->SetMediaType(AUDIOTYPE);
            ((MediaStream*)as)->SetCodecId(CODEC_ID_AAC);

            m_streams.insert(std::make_pair(streamIdx, (MediaStream*)as));
            int32_t ret = as->Initialize(streamIdx, bs, m_initInfo);
            if (ret)
            {
                return ret;
            }
            as = NULL;
        }
        else
        {
            return OMAF_ERROR_INVALID_CODEC;
        }
    }

    return ERROR_NONE;
}

int32_t OmafPackage::CreateExtractorTrackManager()
{
    m_extractorTrackMan = new ExtractorTrackManager(m_initInfo);
    if (!m_extractorTrackMan)
        return OMAF_ERROR_NULL_PTR;

    int32_t ret = m_extractorTrackMan->Initialize(&m_streams);
    if (ret)
        return ret;

    return ERROR_NONE;
}

int32_t OmafPackage::CreateSegmentation()
{
    if (m_sourceMode == OMNIDIRECTIONAL_VIDEO_PACKING)
    {
        m_segmentation = new DefaultSegmentation(&m_streams, m_extractorTrackMan, m_initInfo, m_sourceMode);
    }
    else if (m_sourceMode == MULTIVIEW_VIDEO_PACKING)
    {
        m_segmentation = new MultiViewSegmentation(&m_streams, NULL, m_initInfo, m_sourceMode);
    }

    if (!m_segmentation)
        return OMAF_ERROR_NULL_PTR;

    int32_t ret = m_segmentation->Initialize();
    if (ret)
        return ret;

    return ERROR_NONE;
}

int32_t OmafPackage::InitOmafPackage(InitialInfo *initInfo)
{
    if (!initInfo)
        return OMAF_ERROR_NULL_PTR;

    if (!initInfo->bsBuffers)
        return OMAF_ERROR_NULL_PTR;

    if (!initInfo->videoProcessPluginPath || !initInfo->videoProcessPluginName)
        return OMAF_ERROR_NO_PLUGIN_SET;

    if (initInfo->bsNumAudio && (!initInfo->audioProcessPluginPath || !initInfo->audioProcessPluginName))
        return OMAF_ERROR_NO_PLUGIN_SET;

    m_initInfo = initInfo;
    if (initInfo->logFunction)
        logCallBack = (LogFunction)(initInfo->logFunction);
    else
        logCallBack = GlogFunction; //default log callback function

    uint8_t streamsNumTotal = initInfo->bsNumVideo + initInfo->bsNumAudio;
    uint8_t streamIdx = 0;
    int32_t ret = ERROR_NONE;
    for( ; streamIdx < streamsNumTotal; streamIdx++)
    {
        BSBuffer bsBuffer = initInfo->bsBuffers[streamIdx];
        ret = AddMediaStream(streamIdx, &bsBuffer);
        if (ret)
            return OMAF_ERROR_ADD_MEDIASTREAMS;
    }

    if ((m_initInfo->projType == E_SVIDEO_PLANAR) && m_hasViewSEI)
    {
        m_sourceMode = MULTIVIEW_VIDEO_PACKING;
    }

    if (m_sourceMode == OMNIDIRECTIONAL_VIDEO_PACKING)
    {
        ret = CreateExtractorTrackManager();
        if (ret)
            return OMAF_ERROR_CREATE_EXTRACTORTRACK_MANAGER;
    }

    if (m_initInfo->cmafEnabled && (m_initInfo->segmentationInfo->chunkInfoType == E_ChunkInfoType::E_NO_CHUNKINFO))
    {
        if (m_initInfo->segmentationInfo->isLive)
        {
            m_initInfo->segmentationInfo->chunkInfoType = E_ChunkInfoType::E_CHUNKINFO_CLOC_ONLY;
        }
        else
        {
            m_initInfo->segmentationInfo->chunkInfoType = E_ChunkInfoType::E_CHUNKINFO_SIDX_ONLY;
        }
    }

    ret = CreateSegmentation();
    if (ret)
        return OMAF_ERROR_CREATE_SEGMENTATION;

    return ERROR_NONE;
}

int32_t OmafPackage::SetLogCallBack(LogFunction logFunction)
{
    if (!logFunction)
        return OMAF_ERROR_NULL_PTR;

    logCallBack = logFunction;
    return ERROR_NONE;
}

int32_t OmafPackage::SetFrameInfo(uint8_t streamIdx, FrameBSInfo *frameInfo)
{
    MediaStream *stream = m_streams[streamIdx];
    if (!stream)
        return OMAF_ERROR_NULL_PTR;

    if ((stream->GetMediaType() != VIDEOTYPE) && (stream->GetMediaType() != AUDIOTYPE))
        return OMAF_ERROR_MEDIA_TYPE;

    int32_t ret = ERROR_NONE;
    if (stream->GetMediaType() == VIDEOTYPE)
    {
        ret = ((VideoStream*)stream)->AddFrameInfo(frameInfo);
    }
    else if (stream->GetMediaType() == AUDIOTYPE)
    {
        ret = ((AudioStream*)stream)->AddFrameInfo(frameInfo);
    }

    if (ret)
        return OMAF_ERROR_ADD_FRAMEINFO;

    //correct chunk duration according to GOP size
    if (m_initInfo->cmafEnabled && !m_hasChunkDurCorrected && (stream->GetMediaType() == VIDEOTYPE))
    {
        Rational vsFrameRate = ((VideoStream*)stream)->GetFrameRate();
        if ((vsFrameRate.num == 0) || (vsFrameRate.den == 0))
        {
            return OMAF_ERROR_BAD_PARAM;
        }
        uint32_t frameRate = (uint32_t)(ceil((float)(vsFrameRate.num) / (float)(vsFrameRate.den)));
        uint32_t vsGopSize = 0;
        vsGopSize = ((VideoStream*)stream)->GetGopSize();
        if (vsGopSize)
        {
        }

        if (vsGopSize)
        {
            int64_t gopIntervalTime = (int64_t)((1000 * vsGopSize) / frameRate);
            if (gopIntervalTime == m_initInfo->segmentationInfo->chunkDuration)
            {
                //no change
            }
            else if (gopIntervalTime > m_initInfo->segmentationInfo->chunkDuration)
            {
                m_initInfo->segmentationInfo->chunkDuration = gopIntervalTime;
            }
            else
            {
                uint32_t times = 1;
                while ((gopIntervalTime * times) < m_initInfo->segmentationInfo->chunkDuration)
                {
                    times++;
                }
                m_initInfo->segmentationInfo->chunkDuration = gopIntervalTime * times;
            }
            m_hasChunkDurCorrected = true;
        }
    }

    return ERROR_NONE;
}

void* OmafPackage::VideoSegmentationThread(void* pThis)
{
    OmafPackage *omafPackage = (OmafPackage*)pThis;

    omafPackage->SegmentAllVideoStreams();

    return NULL;
}

void OmafPackage::SegmentAllVideoStreams()
{
    m_segmentation->VideoSegmentation();
}

void* OmafPackage::AudioSegmentationThread(void* pThis)
{
    OmafPackage *omafPackage = (OmafPackage*)pThis;

    omafPackage->SegmentAllAudioStreams();

    return NULL;
}

void OmafPackage::SegmentAllAudioStreams()
{
    m_segmentation->AudioSegmentation();
}

int32_t OmafPackage::OmafPacketStream(uint8_t streamIdx, FrameBSInfo *frameInfo)
{
    //for (uint32_t index = 0; index < 200; index++)
    //{
    //    printf("%0x ", *(frameInfo->data + index));
    //}
    //printf("\n");

    int32_t ret = SetFrameInfo(streamIdx, frameInfo);
    if (ret)
        return ret;

    if (!m_isSegmentationStarted)
    {
        uint32_t vsNum = 0;
        std::map<uint8_t, MediaStream*>::iterator itMS;
        for (itMS = m_streams.begin(); itMS != m_streams.end(); itMS++)
        {
            MediaStream *stream = itMS->second;
            if (stream && (stream->GetMediaType() == VIDEOTYPE))
            {
                VideoStream *vs = (VideoStream*)stream;
                if (!(m_initInfo->cmafEnabled) && (vs->GetBufferedFrameNum() >= (uint32_t)(m_initInfo->segmentationInfo->needBufedFrames)))
                {
                    vsNum++;
                }
                else if ((m_initInfo->cmafEnabled) && m_hasChunkDurCorrected &&
                     (vs->GetBufferedFrameNum() >= (uint32_t)(m_initInfo->segmentationInfo->needBufedFrames)))
                {
                    vsNum++;
                }
            }
        }

        uint32_t asNum = 0;
        for (itMS = m_streams.begin(); itMS != m_streams.end(); itMS++)
        {
            MediaStream *stream = itMS->second;
            if (stream && (stream->GetMediaType() == AUDIOTYPE))
            {
                AudioStream *as = (AudioStream*)stream;
                if (!(m_initInfo->cmafEnabled) && (as->GetBufferedFrameNum() >= (uint32_t)(m_initInfo->segmentationInfo->needBufedFrames)))
                {
                    asNum++;
                }
                else if ((m_initInfo->cmafEnabled) && m_hasChunkDurCorrected &&
                    (as->GetBufferedFrameNum() >= (uint32_t)(m_initInfo->segmentationInfo->needBufedFrames)))
                {
                    asNum++;
                }
            }
        }

        if ((vsNum == m_initInfo->bsNumVideo) && (asNum == m_initInfo->bsNumAudio))
        {
            ret = pthread_create(&m_videoThreadId, NULL, VideoSegmentationThread, this);
            if (ret)
                return OMAF_ERROR_CREATE_THREAD;

            if (m_hasAudio)
            {
                ret = pthread_create(&m_audioThreadId, NULL, AudioSegmentationThread, this);
                if (ret)
                    return OMAF_ERROR_CREATE_THREAD;
            }
            m_isSegmentationStarted = true;
        }
    }

    return ERROR_NONE;
}

int32_t OmafPackage::OmafEndStreams()
{
    if (m_segmentation)
    {
        int32_t ret = m_segmentation->VideoEndSegmentation();
        if (ret)
            return ret;

        if (m_hasAudio)
        {
            ret = m_segmentation->AudioEndSegmentation();
            if (ret)
                return ret;
        }
    }

    return ERROR_NONE;
}

VCD_NS_END
