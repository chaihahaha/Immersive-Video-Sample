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
//! \file:   DefaultSegmentation.cpp
//! \brief:  Default segmentation class implementation
//!
//! Created on April 30, 2019, 6:04 AM
//!

#include "VideoStreamPluginAPI.h"
#include "AudioStreamPluginAPI.h"
#include "DefaultSegmentation.h"
#include "Fraction.h"

#include <unistd.h>
#include <chrono>
#include <cstdint>
#include <sys/time.h>
#include <dlfcn.h>
#include <math.h>

#ifdef _USE_TRACE_
#include "../trace/Bandwidth_tp.h"
#include "../trace/E2E_latency_tp.h"
#endif

VCD_NS_BEGIN

DefaultSegmentation::~DefaultSegmentation()
{
    std::map<MediaStream*, TrackSegmentCtx*>::iterator itTrackCtx;
    for (itTrackCtx = m_streamSegCtx.begin();
        itTrackCtx != m_streamSegCtx.end();
        itTrackCtx++)
    {
        TrackSegmentCtx *trackSegCtxs = itTrackCtx->second;
        MediaStream *stream = itTrackCtx->first;
        if (stream && (stream->GetMediaType() == VIDEOTYPE))
        {
            VideoStream *vs = (VideoStream*)stream;
            uint32_t tilesNum = vs->GetTileInRow() * vs->GetTileInCol();
            for (uint32_t i = 0; i < tilesNum; i++)
            {
               DELETE_MEMORY(trackSegCtxs[i].initSegmenter);
               DELETE_MEMORY(trackSegCtxs[i].dashSegmenter);
            }

            DELETE_ARRAY(trackSegCtxs);
        }
        else if (stream && (stream->GetMediaType() == AUDIOTYPE))
        {
            if (trackSegCtxs)
            {
                DELETE_MEMORY(trackSegCtxs->initSegmenter);
                DELETE_MEMORY(trackSegCtxs->dashSegmenter);
            }

            DELETE_MEMORY(trackSegCtxs);
        }
    }
    m_streamSegCtx.clear();

    std::map<MediaStream*, VCD::MP4::MPDAdaptationSetCtx*>::iterator itASCtx;
    for (itASCtx = m_streamASCtx.begin();
        itASCtx != m_streamASCtx.end(); itASCtx++)
    {
        VCD::MP4::MPDAdaptationSetCtx *asCtxs = itASCtx->second;
        MediaStream *stream = itASCtx->first;
        if (stream && (stream->GetMediaType() == VIDEOTYPE))
        {
            VideoStream *vs = (VideoStream*)stream;
            uint32_t tilesNum = vs->GetTileInRow() * vs->GetTileInCol();
            for (uint32_t i = 0; i < tilesNum; i++)
            {
                DELETE_MEMORY(asCtxs[i].videoInfo);
            }
            DELETE_ARRAY(asCtxs);
        }
        else if (stream && (stream->GetMediaType() == AUDIOTYPE))
        {
            DELETE_MEMORY(asCtxs);
        }
    }
    m_streamASCtx.clear();

    if (m_extractorSegCtx.size())
    {
        std::map<ExtractorTrack*, TrackSegmentCtx*>::iterator itExtractorCtx;
        for (itExtractorCtx = m_extractorSegCtx.begin();
            itExtractorCtx != m_extractorSegCtx.end();
            itExtractorCtx++)
        {
            TrackSegmentCtx *trackSegCtx = itExtractorCtx->second;
            if (trackSegCtx)
            {
                if (trackSegCtx->extractorTrackNalu.data)
                {
                    free(trackSegCtx->extractorTrackNalu.data);
                    trackSegCtx->extractorTrackNalu.data = NULL;
                }

                DELETE_MEMORY(trackSegCtx->initSegmenter);
                DELETE_MEMORY(trackSegCtx->dashSegmenter);
            }
            DELETE_MEMORY(trackSegCtx);
        }

        m_extractorSegCtx.clear();
    }

    std::map<uint32_t, VCD::MP4::MPDAdaptationSetCtx*>::iterator itExtASCtx;
    for (itExtASCtx = m_extractorASCtx.begin();
        itExtASCtx != m_extractorASCtx.end(); itExtASCtx++)
    {
        VCD::MP4::MPDAdaptationSetCtx *asCtx = itExtASCtx->second;
        if (asCtx)
        {
            DELETE_MEMORY(asCtx->videoInfo);
        }
        DELETE_MEMORY(asCtx);
    }
    m_extractorASCtx.clear();

    if (m_extractorThreadIds.size())
    {
        std::map<pthread_t, ExtractorTrack*>::iterator itThreadId;
        for (itThreadId = m_extractorThreadIds.begin(); itThreadId != m_extractorThreadIds.end(); )
        {
            pthread_t oneThread = itThreadId->first;
            if (oneThread)
            {
                pthread_join(oneThread, NULL);
            }
            m_extractorThreadIds.erase(itThreadId++);
        }
        m_extractorThreadIds.clear();
    }

    DELETE_ARRAY(m_videosBitrate);

    if (m_mpdWriterPluginHdl)
    {
        if (m_mpdWriter)
        {
            DestroyMPDWriter* destroyMPDWriter = NULL;
            destroyMPDWriter = (DestroyMPDWriter*)dlsym(m_mpdWriterPluginHdl, "Destroy");
            const char *dlsymErr = dlerror();
            if (dlsymErr)
            {
                return;
            }

            if (!destroyMPDWriter)
            {
                return;
            }

            destroyMPDWriter(m_mpdWriter);
        }
    }
}

int32_t ConvertRwpk(RegionWisePacking *rwpk, VCD::MP4::CodedMeta *codedMeta)
{
    if (!rwpk || !codedMeta)
        return OMAF_ERROR_NULL_PTR;

    VCD::MP4::RegionPacking regionPacking;
    regionPacking.constituentPictMatching = rwpk->constituentPicMatching;
    regionPacking.projPictureWidth = rwpk->projPicWidth;
    regionPacking.projPictureHeight = rwpk->projPicHeight;
    regionPacking.packedPictureWidth = rwpk->packedPicWidth;
    regionPacking.packedPictureHeight = rwpk->packedPicHeight;

    for (uint8_t i = 0; i < rwpk->numRegions; i++)
    {
        VCD::MP4::Region region;
        region.projTop = rwpk->rectRegionPacking[i].projRegTop;
        region.projLeft = rwpk->rectRegionPacking[i].projRegLeft;
        region.projWidth = rwpk->rectRegionPacking[i].projRegWidth;
        region.projHeight = rwpk->rectRegionPacking[i].projRegHeight;
        region.transform = rwpk->rectRegionPacking[i].transformType;
        region.packedTop = rwpk->rectRegionPacking[i].packedRegTop;
        region.packedLeft = rwpk->rectRegionPacking[i].packedRegLeft;
        region.packedWidth = rwpk->rectRegionPacking[i].packedRegWidth;
        region.packedHeight = rwpk->rectRegionPacking[i].packedRegHeight;

        regionPacking.regions.push_back(region);
    }

    codedMeta->regionPacking = regionPacking;

    return ERROR_NONE;
}

int32_t ConvertCovi(SphereRegion *spr, VCD::MP4::CodedMeta *codedMeta)
{
    if (!spr || !codedMeta)
        return OMAF_ERROR_NULL_PTR;

    VCD::MP4::Spherical sphericalCov;
    sphericalCov.cAzimuth = spr->centreAzimuth;
    sphericalCov.cElevation = spr->centreElevation;
    sphericalCov.cTilt = spr->centreTilt;
    sphericalCov.rAzimuth = spr->azimuthRange;
    sphericalCov.rElevation = spr->elevationRange;

    codedMeta->sphericalCoverage = sphericalCov;

    return ERROR_NONE;
}

int32_t FillQualityRank(VCD::MP4::CodedMeta *codedMeta, std::list<PicResolution> *picResList)
{
    if (!picResList)
        return OMAF_ERROR_NULL_PTR;

    VCD::MP4::Quality3d qualityRankCov;

    std::list<PicResolution>::iterator it;
    uint8_t qualityRankStarter = MAINSTREAM_QUALITY_RANK;
    uint8_t resNum = 0;
    for (it = picResList->begin(); it != picResList->end(); it++)
    {
        VCD::MP4::QualityInfo info;
        PicResolution picRes = *it;
        info.origWidth = picRes.width;
        info.origHeight = picRes.height;
        info.qualityRank = qualityRankStarter + resNum;
        VCD::MP4::Spherical sphere;
        sphere.cAzimuth = codedMeta->sphericalCoverage.get().cAzimuth;
        sphere.cElevation = codedMeta->sphericalCoverage.get().cElevation;
        sphere.cTilt = codedMeta->sphericalCoverage.get().cTilt;
        sphere.rAzimuth = codedMeta->sphericalCoverage.get().rAzimuth;
        sphere.rElevation = codedMeta->sphericalCoverage.get().rElevation;
        info.sphere = sphere;
        qualityRankCov.qualityInfo.push_back(info);
        resNum++;
    }
    qualityRankCov.remainingArea = true;
    codedMeta->qualityRankCoverage = qualityRankCov;

    return ERROR_NONE;
}

int32_t DefaultSegmentation::CreateDashMPDWriter()
{
    if (!m_mpdWriterPluginHdl)
    {
        return OMAF_ERROR_NULL_PTR;
    }

    CreateMPDWriter* createMPDWriter = NULL;
    createMPDWriter = (CreateMPDWriter*)dlsym(m_mpdWriterPluginHdl, "Create");
    const char *dlsymErr2 = NULL;
    dlsymErr2 = dlerror();
    if (dlsymErr2)
    {
        return OMAF_ERROR_DLSYM;
    }

    if (!createMPDWriter)
    {
        return OMAF_ERROR_NULL_PTR;
    }

    m_mpdWriter = createMPDWriter(
                        &m_streamASCtx,
                        &m_extractorASCtx,
                        m_segInfo,
                        m_projType,
                        m_frameRate,
                        m_videosNum,
                        m_isCMAFEnabled);

    if (!m_mpdWriter)
    {
        return OMAF_ERROR_NULL_PTR;
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::ConstructTileTrackSegCtx()
{
    std::set<uint64_t> bitRateRanking;

    std::map<uint8_t, MediaStream*>::iterator it;
    for (it = m_streamMap->begin(); it != m_streamMap->end(); it++)
    {
        MediaStream *stream = it->second;
        if (stream->GetMediaType() == VIDEOTYPE)
        {
            m_videosNum++;
            VideoStream *vs = (VideoStream*)stream;
            uint64_t bitRate = vs->GetBitRate();
            bitRateRanking.insert(bitRate);
        }
    }

    if (m_videosNum != bitRateRanking.size())
    {
        return OMAF_ERROR_VIDEO_NUM;
    }
    m_videosBitrate = new uint64_t[m_videosNum];
    if (!m_videosBitrate)
        return OMAF_ERROR_NULL_PTR;

    memset_s(m_videosBitrate, m_videosNum * sizeof(uint64_t), 0);
    std::set<uint64_t>::reverse_iterator rateIter = bitRateRanking.rbegin();
    uint32_t index = 0;
    for ( ; rateIter != bitRateRanking.rend(); rateIter++)
    {
        m_videosBitrate[index] = *rateIter;
        index++;
    }

    for (it = m_streamMap->begin(); it != m_streamMap->end(); it++)
    {
        MediaStream *stream = it->second;
        if (stream->GetMediaType() == VIDEOTYPE)
        {
            VideoStream *vs = (VideoStream*)stream;
            uint16_t vsWidth = vs->GetSrcWidth();
            uint16_t vsHeight = vs->GetSrcHeight();
            TileInfo *tilesInfo = vs->GetAllTilesInfo();
            Rational frameRate = vs->GetFrameRate();
            uint64_t bitRate = vs->GetBitRate();
            uint8_t qualityLevel = bitRateRanking.size();
            std::set<uint64_t>::iterator itBitRate;
            for (itBitRate = bitRateRanking.begin();
                itBitRate != bitRateRanking.end();
                itBitRate++, qualityLevel--)
            {
                if (*itBitRate == bitRate)
                    break;
            }
            m_projType = (VCD::OMAF::ProjectionFormat)vs->GetProjType();
            m_videoSegInfo = vs->GetVideoSegInfo();
            Nalu *vpsNalu = vs->GetVPSNalu();
            if (!vpsNalu || !(vpsNalu->data) || !(vpsNalu->dataSize))
                return OMAF_ERROR_INVALID_HEADER;

            Nalu *spsNalu = vs->GetSPSNalu();
            if (!spsNalu || !(spsNalu->data) || !(spsNalu->dataSize))
                return OMAF_ERROR_INVALID_SPS;

            Nalu *ppsNalu = vs->GetPPSNalu();
            if (!ppsNalu || !(ppsNalu->data) || !(ppsNalu->dataSize))
                return OMAF_ERROR_INVALID_PPS;

            std::vector<uint8_t> vpsData(
                static_cast<const uint8_t*>(vpsNalu->data),
                static_cast<const uint8_t*>(vpsNalu->data) + vpsNalu->dataSize);
            std::vector<uint8_t> spsData(
                static_cast<const uint8_t*>(spsNalu->data),
                static_cast<const uint8_t*>(spsNalu->data) + spsNalu->dataSize);
            std::vector<uint8_t> ppsData(
                static_cast<const uint8_t*>(ppsNalu->data),
                static_cast<const uint8_t*>(ppsNalu->data) + ppsNalu->dataSize);

            uint32_t tilesNum = vs->GetTileInRow() * vs->GetTileInCol();

            RegionWisePacking *rwpk = vs->GetSrcRwpk();

            uint64_t tileBitRate = bitRate / tilesNum;

            VCD::MP4::MPDAdaptationSetCtx *mpdASCtxs = new VCD::MP4::MPDAdaptationSetCtx[tilesNum];
            if (!mpdASCtxs)
                return OMAF_ERROR_NULL_PTR;
            for (uint32_t i = 0; i < tilesNum; i++)
            {
                mpdASCtxs[i].videoInfo = new VCD::MP4::VideoAdaptationSetInfo;
                if (!(mpdASCtxs[i].videoInfo))
                {
                    for (uint32_t j = 0; j < i; j++)
                    {
                        DELETE_MEMORY(mpdASCtxs[j].videoInfo);
                    }
                    DELETE_ARRAY(mpdASCtxs);
                    return OMAF_ERROR_NULL_PTR;
                }
                memset_s(mpdASCtxs[i].videoInfo, sizeof(VCD::MP4::VideoAdaptationSetInfo), 0);
            }

            TrackSegmentCtx *trackSegCtxs = new TrackSegmentCtx[tilesNum];
            if (!trackSegCtxs)
            {
                for (uint32_t i = 0; i < tilesNum; i++)
                {
                    DELETE_MEMORY(mpdASCtxs[i].videoInfo);
                }
                DELETE_ARRAY(mpdASCtxs);
                return OMAF_ERROR_NULL_PTR;
            }

            std::map<uint32_t, VCD::MP4::TrackId> tilesTrackIndex;
            for (uint32_t i = 0; i < tilesNum; i++)
            {
                trackSegCtxs[i].isAudio = false;
                trackSegCtxs[i].isExtractorTrack = false;
                trackSegCtxs[i].tileInfo = &(tilesInfo[i]);
                trackSegCtxs[i].tileIdx = i;
                trackSegCtxs[i].trackIdx = m_trackIdStarter + i;

                //set InitSegConfig
                TrackConfig trackConfig{};
                trackConfig.meta.trackId = m_trackIdStarter + i;
                trackConfig.meta.timescale = VCD::MP4::FractU64(frameRate.den, frameRate.num * 1000); //?
                trackConfig.meta.type = VCD::MP4::TypeOfMedia::Video;
                trackConfig.pipelineOutput = DataInputFormat::VideoMono;
                trackSegCtxs[i].dashInitCfg.tracks.insert(std::make_pair(trackSegCtxs[i].trackIdx, trackConfig));
                m_allTileTracks.insert(std::make_pair(trackSegCtxs[i].trackIdx, trackConfig));
                trackSegCtxs[i].dashInitCfg.fragmented = true;
                trackSegCtxs[i].dashInitCfg.writeToBitstream = true;
                trackSegCtxs[i].dashInitCfg.packedSubPictures = true;
                trackSegCtxs[i].dashInitCfg.mode = OperatingMode::OMAF;
                trackSegCtxs[i].dashInitCfg.streamIds.push_back(trackConfig.meta.trackId.GetIndex());
                snprintf(trackSegCtxs[i].dashInitCfg.initSegName, 1024, "%s%s_track%ld.init.mp4", m_segInfo->dirName, m_segInfo->outName, m_trackIdStarter + i);

                //set GeneralSegConfig
                uint32_t frameRateInt = (uint32_t)(ceil((float)(frameRate.num) / (float)(frameRate.den)));
                trackSegCtxs[i].dashCfg.sgtDuration = VCD::MP4::FractU64(frameRate.den * m_videoSegInfo->segDur * 1000 * frameRateInt, frameRate.num * 1000);
                if (!m_isCMAFEnabled)
                {
                    trackSegCtxs[i].dashCfg.subsgtDuration = trackSegCtxs[i].dashCfg.sgtDuration / VCD::MP4::FrameDuration{ 1, 1}; //?
                }
                else
                {
                    trackSegCtxs[i].dashCfg.subsgtDuration = VCD::MP4::FractU64(m_segInfo->chunkDuration, m_segInfo->segDuration * 1000) / VCD::MP4::FrameDuration{ 1, 1};
                    if (i == 0)
                    {
                        uint64_t subSegNumInSeg = (uint64_t)(trackSegCtxs[i].dashCfg.subsgtDuration.get().m_den / trackSegCtxs[i].dashCfg.subsgtDuration.get().m_num);
                    }
                }
                trackSegCtxs[i].dashCfg.needCheckIDR = true;

                VCD::MP4::TrackMeta trackMeta{};
                trackMeta.trackId = trackSegCtxs[i].trackIdx;
                trackMeta.timescale = VCD::MP4::FractU64(frameRate.den, frameRate.num * 1000); //?
                trackMeta.type = VCD::MP4::TypeOfMedia::Video;
                trackSegCtxs[i].dashCfg.tracks.insert(std::make_pair(trackSegCtxs[i].trackIdx, trackMeta));

                trackSegCtxs[i].dashCfg.useSeparatedSidx = false;
                trackSegCtxs[i].dashCfg.streamsIdx.push_back(it->first);
                snprintf(trackSegCtxs[i].dashCfg.trackSegBaseName, 1024, "%s%s_track%ld", m_segInfo->dirName, m_segInfo->outName, m_trackIdStarter + i);
                trackSegCtxs[i].dashCfg.cmafEnabled = m_isCMAFEnabled;
                trackSegCtxs[i].dashCfg.chunkInfoType = m_segInfo->chunkInfoType;

                //setup VCD::MP4::SegmentWriterBase
                int32_t ret = ERROR_NONE;
                trackSegCtxs[i].segWriterPluginHdl = m_segWriterPluginHdl;
                ret = trackSegCtxs[i].CreateDashSegmentWriter();
                if (ret)
                {
                    for (uint32_t id = 0; id < i; id++)
                    {
                        DELETE_MEMORY(trackSegCtxs[id].initSegmenter);
                        DELETE_MEMORY(trackSegCtxs[id].dashSegmenter);
                    }
                    DELETE_ARRAY(trackSegCtxs);

                    for (uint32_t id = 0; id < tilesNum; id++)
                    {
                        DELETE_MEMORY(mpdASCtxs[id].videoInfo);
                    }
                    DELETE_ARRAY(mpdASCtxs);

                    return ret;
                }

                //setup DashInitSegmenter
                trackSegCtxs[i].initSegmenter = new DashInitSegmenter(&(trackSegCtxs[i].dashInitCfg));
                if (!(trackSegCtxs[i].initSegmenter))
                {
                    for (uint32_t id = 0; id < i; id++)
                    {
                        DELETE_MEMORY(trackSegCtxs[id].initSegmenter);
                        DELETE_MEMORY(trackSegCtxs[id].dashSegmenter);
                    }

                    DELETE_ARRAY(trackSegCtxs);

                    for (uint32_t id = 0; id < tilesNum; id++)
                    {
                        DELETE_MEMORY(mpdASCtxs[id].videoInfo);
                    }
                    DELETE_ARRAY(mpdASCtxs);

                    return OMAF_ERROR_NULL_PTR;
                }
                (trackSegCtxs[i].initSegmenter)->SetSegmentWriter(trackSegCtxs[i].segWriter);

                //setup DashSegmenter
                trackSegCtxs[i].dashSegmenter = new DashSegmenter(&(trackSegCtxs[i].dashCfg), true);
                if (!(trackSegCtxs[i].dashSegmenter))
                {
                    for (uint32_t id = 0; id < i; id++)
                    {
                        DELETE_MEMORY(trackSegCtxs[id].initSegmenter);
                        DELETE_MEMORY(trackSegCtxs[id].dashSegmenter);
                    }

                    DELETE_MEMORY(trackSegCtxs[i].initSegmenter);
                    DELETE_ARRAY(trackSegCtxs);

                    for (uint32_t id = 0; id < tilesNum; id++)
                    {
                        DELETE_MEMORY(mpdASCtxs[id].videoInfo);
                    }
                    DELETE_ARRAY(mpdASCtxs);

                    return OMAF_ERROR_NULL_PTR;
                }
                (trackSegCtxs[i].dashSegmenter)->SetSegmentWriter(trackSegCtxs[i].segWriter);

                trackSegCtxs[i].qualityRanking = qualityLevel;

                //setup CodedMeta
                trackSegCtxs[i].codedMeta.presIndex = 0;
                trackSegCtxs[i].codedMeta.codingIndex = 0;
                trackSegCtxs[i].codedMeta.codingTime = VCD::MP4::FrameTime{ 0, 1 };
                trackSegCtxs[i].codedMeta.presTime = VCD::MP4::FrameTime{(int64_t) (frameRate.den * 1000), (int64_t)(frameRate.num * 1000) };
                trackSegCtxs[i].codedMeta.duration = VCD::MP4::FrameDuration{ frameRate.den * 1000, frameRate.num * 1000};
                trackSegCtxs[i].codedMeta.trackId = trackSegCtxs[i].trackIdx;
                trackSegCtxs[i].codedMeta.inCodingOrder = true;
                trackSegCtxs[i].codedMeta.format = VCD::MP4::CodedFormat::H265;
                trackSegCtxs[i].codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::VPS, vpsData));
                trackSegCtxs[i].codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::SPS, spsData));
                trackSegCtxs[i].codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::PPS, ppsData));
                trackSegCtxs[i].codedMeta.width = tilesInfo[i].tileWidth;
                trackSegCtxs[i].codedMeta.height = tilesInfo[i].tileHeight;
                trackSegCtxs[i].codedMeta.bitrate.avgBitrate = tileBitRate;
                trackSegCtxs[i].codedMeta.bitrate.maxBitrate = 0;
                trackSegCtxs[i].codedMeta.type = VCD::MP4::FrameType::IDR;
                trackSegCtxs[i].codedMeta.segmenterMeta.segmentDuration = VCD::MP4::FrameDuration{ 0, 1 }; //?


                RegionWisePacking regionPacking;
                regionPacking.constituentPicMatching = rwpk->constituentPicMatching;
                regionPacking.numRegions = 1;
                regionPacking.projPicWidth = rwpk->projPicWidth;
                regionPacking.projPicHeight = rwpk->projPicHeight;
                regionPacking.packedPicWidth = rwpk->packedPicWidth;
                regionPacking.packedPicHeight = rwpk->packedPicHeight;
                regionPacking.rectRegionPacking = new RectangularRegionWisePacking[1];
                if (!(regionPacking.rectRegionPacking))
                {
                    for (uint32_t id = 0; id < (i + 1); id++)
                    {
                        DELETE_MEMORY(trackSegCtxs[id].initSegmenter);
                        DELETE_MEMORY(trackSegCtxs[id].dashSegmenter);
                    }

                    DELETE_ARRAY(trackSegCtxs);

                    for (uint32_t id = 0; id < tilesNum; id++)
                    {
                        DELETE_MEMORY(mpdASCtxs[id].videoInfo);
                    }
                    DELETE_ARRAY(mpdASCtxs);

                    return OMAF_ERROR_NULL_PTR;
                }

                memcpy_s(&(regionPacking.rectRegionPacking[0]), sizeof(RectangularRegionWisePacking),
                        &(rwpk->rectRegionPacking[i]), sizeof(RectangularRegionWisePacking));
                ConvertRwpk(&(regionPacking), &(trackSegCtxs[i].codedMeta));
                DELETE_ARRAY(regionPacking.rectRegionPacking);


                if (m_projType == VCD::OMAF::ProjectionFormat::PF_ERP)
                {
                    trackSegCtxs[i].codedMeta.projection = VCD::MP4::OmafProjectionType::EQUIRECTANGULAR;
                }
                else if (m_projType == VCD::OMAF::ProjectionFormat::PF_CUBEMAP)
                {
                    trackSegCtxs[i].codedMeta.projection = VCD::MP4::OmafProjectionType::CUBEMAP;
                }
                else if (m_projType == VCD::OMAF::ProjectionFormat::PF_PLANAR)
                {
                    trackSegCtxs[i].codedMeta.projection = VCD::MP4::OmafProjectionType::PLANAR;
                }
                else
                {
                    for (uint32_t id = 0; id < (i + 1); id++)
                    {
                        DELETE_MEMORY(trackSegCtxs[id].initSegmenter);
                        DELETE_MEMORY(trackSegCtxs[id].dashSegmenter);
                    }

                    DELETE_ARRAY(trackSegCtxs);

                    for (uint32_t id = 0; id < tilesNum; id++)
                    {
                        DELETE_MEMORY(mpdASCtxs[id].videoInfo);
                    }
                    DELETE_ARRAY(mpdASCtxs);

                    return OMAF_ERROR_INVALID_PROJECTIONTYPE;
                }

                trackSegCtxs[i].codedMeta.isEOS = false;

                tilesTrackIndex.insert(std::make_pair(i, trackSegCtxs[i].trackIdx));

                m_trackSegCtx.insert(std::make_pair(trackSegCtxs[i].trackIdx, &(trackSegCtxs[i])));

                mpdASCtxs[i].videoInfo->fullWidth = vsWidth;
                mpdASCtxs[i].videoInfo->fullHeight = vsHeight;
                mpdASCtxs[i].videoInfo->tileWidth = tilesInfo[i].tileWidth;
                mpdASCtxs[i].videoInfo->tileHeight = tilesInfo[i].tileHeight;
                mpdASCtxs[i].videoInfo->tileHPos = tilesInfo[i].horizontalPos;
                mpdASCtxs[i].videoInfo->tileVPos = tilesInfo[i].verticalPos;
                mpdASCtxs[i].videoInfo->tileCubemapHPos = tilesInfo[i].defaultHorPos;
                mpdASCtxs[i].videoInfo->tileCubemapVPos = tilesInfo[i].defaultVerPos;
                mpdASCtxs[i].trackIdx = trackSegCtxs[i].trackIdx;
                mpdASCtxs[i].codedMeta = trackSegCtxs[i].codedMeta;
                mpdASCtxs[i].qualityRanking = trackSegCtxs[i].qualityRanking;
            }
            m_trackIdStarter += tilesNum;
            m_streamSegCtx.insert(std::make_pair(stream, trackSegCtxs));
            m_streamASCtx.insert(std::make_pair(stream, mpdASCtxs));
            m_framesIsKey.insert(std::make_pair(stream, true));
            m_streamsIsEOS.insert(std::make_pair(stream, false));
            m_tilesTrackIdxs.insert(std::make_pair(it->first, tilesTrackIndex));
        }
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::ConstructExtractorTrackSegCtx()
{
    std::map<uint16_t, ExtractorTrack*> *extractorTracks = m_extractorTrackMan->GetAllExtractorTracks();
    if (extractorTracks->size())
    {
        std::map<uint16_t, ExtractorTrack*>::iterator it1;
        for (it1 = extractorTracks->begin(); it1 != extractorTracks->end(); it1++)
        {
            ExtractorTrack *extractorTrack = it1->second;
            Nalu *vpsNalu = extractorTrack->GetVPS();
            Nalu *spsNalu = extractorTrack->GetSPS();
            Nalu *ppsNalu = extractorTrack->GetPPS();

            std::vector<uint8_t> vpsData(
                static_cast<const uint8_t*>(vpsNalu->data),
                static_cast<const uint8_t*>(vpsNalu->data) + vpsNalu->dataSize);
            std::vector<uint8_t> spsData(
                static_cast<const uint8_t*>(spsNalu->data),
                static_cast<const uint8_t*>(spsNalu->data) + spsNalu->dataSize);
            std::vector<uint8_t> ppsData(
                static_cast<const uint8_t*>(ppsNalu->data),
                static_cast<const uint8_t*>(ppsNalu->data) + ppsNalu->dataSize);

            RegionWisePacking *rwpk = extractorTrack->GetRwpk();
            ContentCoverage   *covi = extractorTrack->GetCovi();
            std::list<PicResolution> *picResList = extractorTrack->GetPicRes();
            Nalu *projSEI = extractorTrack->GetProjectionSEI();
            Nalu *rwpkSEI = extractorTrack->GetRwpkSEI();

            VCD::MP4::MPDAdaptationSetCtx *mpdASCtx = new VCD::MP4::MPDAdaptationSetCtx;
            if (!mpdASCtx)
                return OMAF_ERROR_NULL_PTR;

            mpdASCtx->videoInfo = NULL;

            TrackSegmentCtx *trackSegCtx = new TrackSegmentCtx;
            if (!trackSegCtx)
            {
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_NULL_PTR;
            }

            trackSegCtx->isAudio = false;
            trackSegCtx->isExtractorTrack = true;
            trackSegCtx->extractorTrackIdx = it1->first;
            trackSegCtx->extractors = extractorTrack->GetAllExtractors();
            memset_s(&(trackSegCtx->extractorTrackNalu), sizeof(Nalu), 0);
            trackSegCtx->extractorTrackNalu.dataSize = projSEI->dataSize + rwpkSEI->dataSize;
            trackSegCtx->extractorTrackNalu.data = new uint8_t[trackSegCtx->extractorTrackNalu.dataSize];
            if (!(trackSegCtx->extractorTrackNalu.data))
            {
                DELETE_MEMORY(mpdASCtx);
                DELETE_MEMORY(trackSegCtx);
                return OMAF_ERROR_NULL_PTR;
            }

            memcpy_s(trackSegCtx->extractorTrackNalu.data, projSEI->dataSize, projSEI->data, projSEI->dataSize);
            memcpy_s(trackSegCtx->extractorTrackNalu.data + projSEI->dataSize, rwpkSEI->dataSize, rwpkSEI->data, rwpkSEI->dataSize);

            TilesMergeDirectionInCol *tilesMergeDir = extractorTrack->GetTilesMergeDir();
            std::list<TilesInCol*>::iterator itCol;
            for (itCol = tilesMergeDir->tilesArrangeInCol.begin();
                itCol != tilesMergeDir->tilesArrangeInCol.end(); itCol++)
            {
                TilesInCol *tileCol = *itCol;
                std::list<SingleTile*>::iterator itTile;
                for (itTile = tileCol->begin(); itTile != tileCol->end(); itTile++)
                {
                    SingleTile *tile = *itTile;
                    uint8_t vsIdx    = tile->streamIdxInMedia;
                    uint8_t origTileIdx  = tile->origTileIdx;

                    std::map<uint8_t, std::map<uint32_t, VCD::MP4::TrackId>>::iterator itTilesIdxs;
                    itTilesIdxs = m_tilesTrackIdxs.find(vsIdx);
                    if (itTilesIdxs == m_tilesTrackIdxs.end())
                    {
                        DELETE_ARRAY(trackSegCtx->extractorTrackNalu.data);
                        DELETE_MEMORY(trackSegCtx);
                        DELETE_MEMORY(mpdASCtx);
                        return OMAF_ERROR_STREAM_NOT_FOUND;
                    }
                    std::map<uint32_t, VCD::MP4::TrackId> tilesIndex = itTilesIdxs->second;
                    VCD::MP4::TrackId foundTrackId = tilesIndex[origTileIdx];
                    trackSegCtx->refTrackIdxs.push_back(foundTrackId);
                }
            }

            trackSegCtx->trackIdx = DEFAULT_EXTRACTORTRACK_TRACKIDBASE + trackSegCtx->extractorTrackIdx;

            //set up InitSegConfig
            std::set<VCD::MP4::TrackId> allTrackIds;
            std::map<VCD::MP4::TrackId, TrackConfig>::iterator itTrack;
            for (itTrack = m_allTileTracks.begin(); itTrack != m_allTileTracks.end(); itTrack++)
            {
                trackSegCtx->dashInitCfg.tracks.insert(std::make_pair(itTrack->first, itTrack->second));
                allTrackIds.insert(itTrack->first);
            }

            TrackConfig trackConfig{};
            trackConfig.meta.trackId = trackSegCtx->trackIdx;
            trackConfig.meta.timescale = VCD::MP4::FractU64(m_frameRate.den, m_frameRate.num * 1000); //?
            trackConfig.meta.type = VCD::MP4::TypeOfMedia::Video;
            trackConfig.trackReferences.insert(std::make_pair("scal", allTrackIds));
            trackConfig.pipelineOutput = DataInputFormat::VideoMono;
            trackSegCtx->dashInitCfg.tracks.insert(std::make_pair(trackSegCtx->trackIdx, trackConfig));

            trackSegCtx->dashInitCfg.fragmented = true;
            trackSegCtx->dashInitCfg.writeToBitstream = true;
            trackSegCtx->dashInitCfg.packedSubPictures = true;
            trackSegCtx->dashInitCfg.mode = OperatingMode::OMAF;
            trackSegCtx->dashInitCfg.streamIds.push_back(trackSegCtx->trackIdx.GetIndex());
            std::set<VCD::MP4::TrackId>::iterator itId;
            for (itId = allTrackIds.begin(); itId != allTrackIds.end(); itId++)
            {
                trackSegCtx->dashInitCfg.streamIds.push_back((*itId).GetIndex());
            }
            snprintf(trackSegCtx->dashInitCfg.initSegName, 1024, "%s%s_track%d.init.mp4", m_segInfo->dirName, m_segInfo->outName, trackSegCtx->trackIdx.GetIndex());

            //set up GeneralSegConfig
            uint32_t frameRateInt = (uint32_t)(ceil((float)(m_frameRate.num) / (float)(m_frameRate.den)));
            trackSegCtx->dashCfg.sgtDuration = VCD::MP4::FractU64(m_frameRate.den * m_videoSegInfo->segDur * 1000 * frameRateInt, m_frameRate.num * 1000);

            if (!m_isCMAFEnabled)
            {
                trackSegCtx->dashCfg.subsgtDuration = trackSegCtx->dashCfg.sgtDuration / VCD::MP4::FrameDuration{ 1, 1}; //?
            }
            else
            {
                trackSegCtx->dashCfg.subsgtDuration = VCD::MP4::FractU64(m_segInfo->chunkDuration, m_segInfo->segDuration * 1000) / VCD::MP4::FrameDuration{ 1, 1};
            }
            trackSegCtx->dashCfg.needCheckIDR = true;

            VCD::MP4::TrackMeta trackMeta{};
            trackMeta.trackId = trackSegCtx->trackIdx;
            trackMeta.timescale = VCD::MP4::FractU64(m_frameRate.den, m_frameRate.num * 1000); //?
            trackMeta.type = VCD::MP4::TypeOfMedia::Video;
            trackSegCtx->dashCfg.tracks.insert(std::make_pair(trackSegCtx->trackIdx, trackMeta));

            trackSegCtx->dashCfg.useSeparatedSidx = false;
            trackSegCtx->dashCfg.streamsIdx.push_back(trackSegCtx->trackIdx.GetIndex());
            snprintf(trackSegCtx->dashCfg.trackSegBaseName, 1024, "%s%s_track%d", m_segInfo->dirName, m_segInfo->outName, trackSegCtx->trackIdx.GetIndex());
            trackSegCtx->dashCfg.cmafEnabled = m_isCMAFEnabled;
            trackSegCtx->dashCfg.chunkInfoType = m_segInfo->chunkInfoType;

            //setup VCD::MP4::SegmentWriterBase
            int32_t ret = ERROR_NONE;
            trackSegCtx->segWriterPluginHdl = m_segWriterPluginHdl;
            ret = trackSegCtx->CreateDashSegmentWriter();
            if (ret)
            {
                DELETE_ARRAY(trackSegCtx->extractorTrackNalu.data);
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);

                return ret;
            }

            //set up DashInitSegmenter
            trackSegCtx->initSegmenter = new DashInitSegmenter(&(trackSegCtx->dashInitCfg));
            if (!(trackSegCtx->initSegmenter))
            {
                DELETE_ARRAY(trackSegCtx->extractorTrackNalu.data);
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_NULL_PTR;
            }
            (trackSegCtx->initSegmenter)->SetSegmentWriter(trackSegCtx->segWriter);

            //set up DashSegmenter
            trackSegCtx->dashSegmenter = new DashSegmenter(&(trackSegCtx->dashCfg), true);
            if (!(trackSegCtx->dashSegmenter))
            {
                DELETE_ARRAY(trackSegCtx->extractorTrackNalu.data);
                DELETE_MEMORY(trackSegCtx->initSegmenter);
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_NULL_PTR;
            }
            (trackSegCtx->dashSegmenter)->SetSegmentWriter(trackSegCtx->segWriter);

            //set up CodedMeta
            trackSegCtx->codedMeta.presIndex = 0;
            trackSegCtx->codedMeta.codingIndex = 0;
            trackSegCtx->codedMeta.codingTime = VCD::MP4::FrameTime{ 0, 1 };
            trackSegCtx->codedMeta.presTime = VCD::MP4::FrameTime{ (int64_t)(m_frameRate.den * 1000), (int64_t)(m_frameRate.num * 1000) };
            trackSegCtx->codedMeta.duration = VCD::MP4::FrameDuration{ m_frameRate.den * 1000, m_frameRate.num * 1000};
            trackSegCtx->codedMeta.trackId = trackSegCtx->trackIdx;
            trackSegCtx->codedMeta.inCodingOrder = true;
            trackSegCtx->codedMeta.format = VCD::MP4::CodedFormat::H265Extractor;
            trackSegCtx->codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::VPS, vpsData));
            trackSegCtx->codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::SPS, spsData));
            trackSegCtx->codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::PPS, ppsData));
            trackSegCtx->codedMeta.width = rwpk->packedPicWidth;
            trackSegCtx->codedMeta.height = rwpk->packedPicHeight;
            trackSegCtx->codedMeta.bitrate.avgBitrate = 0;
            trackSegCtx->codedMeta.bitrate.maxBitrate = 0;
            trackSegCtx->codedMeta.type = VCD::MP4::FrameType::IDR;
            trackSegCtx->codedMeta.segmenterMeta.segmentDuration = VCD::MP4::FrameDuration{ 0, 1 }; //?
            ConvertRwpk(rwpk, &(trackSegCtx->codedMeta));
            ConvertCovi(covi->sphereRegions, &(trackSegCtx->codedMeta));

            FillQualityRank(&(trackSegCtx->codedMeta), picResList);

            if (m_projType == VCD::OMAF::ProjectionFormat::PF_ERP)
            {
                trackSegCtx->codedMeta.projection = VCD::MP4::OmafProjectionType::EQUIRECTANGULAR;
            }
            else if (m_projType == VCD::OMAF::ProjectionFormat::PF_CUBEMAP)
            {
                trackSegCtx->codedMeta.projection = VCD::MP4::OmafProjectionType::CUBEMAP;
            }
            else if (m_projType == VCD::OMAF::ProjectionFormat::PF_PLANAR)
            {
                trackSegCtx->codedMeta.projection = VCD::MP4::OmafProjectionType::PLANAR;
            }
            else
            {
                DELETE_ARRAY(trackSegCtx->extractorTrackNalu.data);
                DELETE_MEMORY(trackSegCtx->initSegmenter);
                DELETE_MEMORY(trackSegCtx->dashSegmenter);
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_INVALID_PROJECTIONTYPE;
            }

            trackSegCtx->codedMeta.isEOS = false;

            mpdASCtx->refTrackIdxs = trackSegCtx->refTrackIdxs;
            mpdASCtx->trackIdx = trackSegCtx->trackIdx;
            mpdASCtx->codedMeta = trackSegCtx->codedMeta;
            mpdASCtx->qualityRanking = trackSegCtx->qualityRanking;

            m_extractorSegCtx.insert(std::make_pair(extractorTrack, trackSegCtx));
            m_extractorASCtx.insert(std::make_pair(mpdASCtx->trackIdx.GetIndex(), mpdASCtx));
        }
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::ConstructAudioTrackSegCtx()
{
    uint8_t audioId = 0;
    std::map<uint8_t, MediaStream*>::iterator it;
    for (it = m_streamMap->begin(); it != m_streamMap->end(); it++)
    {
        uint8_t strId = it->first;
        MediaStream *stream = it->second;
        if (stream && (stream->GetMediaType() == AUDIOTYPE))
        {
            AudioStream *as = (AudioStream*)stream;
            uint32_t frequency = as->GetSampleRate();
            uint8_t chlConfig  = as->GetChannelNum();
            uint16_t bitRate   = as->GetBitRate();
            std::vector<uint8_t> packedAudioSpecCfg = as->GetPackedSpecCfg();

            VCD::MP4::MPDAdaptationSetCtx *mpdASCtx = new VCD::MP4::MPDAdaptationSetCtx;
            if (!mpdASCtx)
                return OMAF_ERROR_NULL_PTR;

            mpdASCtx->videoInfo = NULL;

            TrackSegmentCtx *trackSegCtx = new TrackSegmentCtx;
            if (!trackSegCtx)
            {
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_NULL_PTR;
            }

            trackSegCtx->isAudio          = true;
            trackSegCtx->isExtractorTrack = false;
            trackSegCtx->tileInfo         = NULL;
            trackSegCtx->tileIdx          = 0;
            trackSegCtx->extractorTrackIdx = 0;
            trackSegCtx->extractors        = NULL;
            trackSegCtx->trackIdx          = DEFAULT_AUDIOTRACK_TRACKIDBASE + (uint64_t)audioId;

            TrackConfig trackConfig{};
            trackConfig.meta.trackId = trackSegCtx->trackIdx;
            trackConfig.meta.timescale = VCD::MP4::FractU64(1, frequency);
            trackConfig.meta.type = VCD::MP4::TypeOfMedia::Audio;
            trackConfig.pipelineOutput = DataInputFormat::Audio;
            trackSegCtx->dashInitCfg.tracks.insert(std::make_pair(trackSegCtx->trackIdx, trackConfig));
            trackSegCtx->dashInitCfg.fragmented = true;
            trackSegCtx->dashInitCfg.writeToBitstream = true;
            trackSegCtx->dashInitCfg.packedSubPictures = true;
            trackSegCtx->dashInitCfg.mode = OperatingMode::OMAF;
            trackSegCtx->dashInitCfg.streamIds.push_back(trackConfig.meta.trackId.GetIndex());
            snprintf(trackSegCtx->dashInitCfg.initSegName, 1024, "%s%s_track%ld.init.mp4", m_segInfo->dirName, m_segInfo->outName, (DEFAULT_AUDIOTRACK_TRACKIDBASE + (uint64_t)audioId));

            //set GeneralSegConfig
            trackSegCtx->dashCfg.sgtDuration = VCD::MP4::FractU64(m_segInfo->segDuration, 1); //?
            if (!m_isCMAFEnabled)
            {
                trackSegCtx->dashCfg.subsgtDuration = trackSegCtx->dashCfg.sgtDuration / VCD::MP4::FrameDuration{ 1, 1}; //?
            }
            else
            {
                trackSegCtx->dashCfg.subsgtDuration = VCD::MP4::FractU64(m_segInfo->chunkDuration, m_segInfo->segDuration * 1000) / VCD::MP4::FrameDuration{ 1, 1};
            }
            trackSegCtx->dashCfg.needCheckIDR = true;

            VCD::MP4::TrackMeta trackMeta{};
            trackMeta.trackId = trackSegCtx->trackIdx;
            trackMeta.timescale = VCD::MP4::FractU64(1, frequency);
            trackMeta.type = VCD::MP4::TypeOfMedia::Audio;
            trackSegCtx->dashCfg.tracks.insert(std::make_pair(trackSegCtx->trackIdx, trackMeta));

            trackSegCtx->dashCfg.useSeparatedSidx = false;
            trackSegCtx->dashCfg.streamsIdx.push_back(strId);
            snprintf(trackSegCtx->dashCfg.trackSegBaseName, 1024, "%s%s_track%ld", m_segInfo->dirName, m_segInfo->outName, (DEFAULT_AUDIOTRACK_TRACKIDBASE + (uint64_t)audioId));
            trackSegCtx->dashCfg.cmafEnabled = m_isCMAFEnabled;
            trackSegCtx->dashCfg.chunkInfoType = m_segInfo->chunkInfoType;

            //setup VCD::MP4::SegmentWriterBase
            int32_t ret = ERROR_NONE;
            trackSegCtx->segWriterPluginHdl = m_segWriterPluginHdl;
            ret = trackSegCtx->CreateDashSegmentWriter();
            if (ret)
            {
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);
                return ret;
            }

            //setup DashInitSegmenter
            trackSegCtx->initSegmenter = new DashInitSegmenter(&(trackSegCtx->dashInitCfg));
            if (!(trackSegCtx->initSegmenter))
            {
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_NULL_PTR;
            }
            (trackSegCtx->initSegmenter)->SetSegmentWriter(trackSegCtx->segWriter);

            //setup DashSegmenter
            trackSegCtx->dashSegmenter = new DashSegmenter(&(trackSegCtx->dashCfg), true);
            if (!(trackSegCtx->dashSegmenter))
            {
                DELETE_MEMORY(trackSegCtx->initSegmenter);
                DELETE_MEMORY(trackSegCtx);
                DELETE_MEMORY(mpdASCtx);
                return OMAF_ERROR_NULL_PTR;
            }
            (trackSegCtx->dashSegmenter)->SetSegmentWriter(trackSegCtx->segWriter);

            trackSegCtx->qualityRanking = DEFAULT_QUALITY_RANK;

            //setup CodedMeta
            trackSegCtx->codedMeta.presIndex = 0;
            trackSegCtx->codedMeta.codingIndex = 0;
            trackSegCtx->codedMeta.codingTime = VCD::MP4::FrameTime{ 0, 1 };
            trackSegCtx->codedMeta.presTime = VCD::MP4::FrameTime{ 0, 1000 };
            trackSegCtx->codedMeta.trackId = trackSegCtx->trackIdx;
            trackSegCtx->codedMeta.inCodingOrder = true;
            trackSegCtx->codedMeta.format = VCD::MP4::CodedFormat::AAC;
            trackSegCtx->codedMeta.duration = VCD::MP4::FrameDuration{SAMPLES_NUM_IN_FRAME, frequency};
            trackSegCtx->codedMeta.channelCfg = chlConfig;
            trackSegCtx->codedMeta.samplingFreq = frequency;
            trackSegCtx->codedMeta.type = VCD::MP4::FrameType::IDR;
            trackSegCtx->codedMeta.bitrate.avgBitrate = bitRate;
            trackSegCtx->codedMeta.bitrate.maxBitrate = 0;//?
            trackSegCtx->codedMeta.decoderConfig.insert(std::make_pair(VCD::MP4::ConfigType::AudioSpecificConfig, packedAudioSpecCfg));
            trackSegCtx->codedMeta.isEOS = false;

            trackSegCtx->isEOS = false;

            mpdASCtx->trackIdx = trackSegCtx->trackIdx;
            mpdASCtx->codedMeta = trackSegCtx->codedMeta;

            m_streamSegCtx.insert(std::make_pair(stream, trackSegCtx));
            m_streamASCtx.insert(std::make_pair(stream, mpdASCtx));
        }
    }

    m_audioSegCtxsConsted = true;
    return ERROR_NONE;
}

int32_t DefaultSegmentation::VideoEndSegmentation()
{
    if (m_streamMap->size())
    {
        std::map<uint8_t, MediaStream*>::iterator it = m_streamMap->begin();
        for ( ; it != m_streamMap->end(); it++)
        {
            MediaStream *stream = it->second;
            if (stream)
            {
                if (stream->GetMediaType() == VIDEOTYPE)
                {
                    int32_t ret = EndEachVideo(stream);
                    if (ret)
                        return ret;
                }
            }
        }
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::AudioEndSegmentation()
{
    if (m_streamMap->size())
    {
        std::map<uint8_t, MediaStream*>::iterator it = m_streamMap->begin();
        for ( ; it != m_streamMap->end(); it++)
        {
            MediaStream *stream = it->second;
            if (stream)
            {
                if (stream->GetMediaType() == AUDIOTYPE)
                {
                    int32_t ret = EndEachAudio(stream);
                    if (ret)
                        return ret;
                }
            }
        }
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::WriteSegmentForEachVideo(MediaStream *stream, bool isKeyFrame, bool isEOS)
{
    if (!stream)
        return OMAF_ERROR_NULL_PTR;

    VideoStream *vs = (VideoStream*)stream;

    std::map<MediaStream*, TrackSegmentCtx*>::iterator itStreamTrack;
    itStreamTrack = m_streamSegCtx.find(stream);
    if (itStreamTrack == m_streamSegCtx.end())
        return OMAF_ERROR_STREAM_NOT_FOUND;

    TrackSegmentCtx *trackSegCtxs = itStreamTrack->second;

    uint32_t tilesNum = vs->GetTileInRow() * vs->GetTileInCol();
    for (uint32_t tileIdx = 0; tileIdx < tilesNum; tileIdx++)
    {
        DashSegmenter *dashSegmenter = trackSegCtxs[tileIdx].dashSegmenter;
        if (!dashSegmenter)
            return OMAF_ERROR_NULL_PTR;

        if (isKeyFrame)
            trackSegCtxs[tileIdx].codedMeta.type = VCD::MP4::FrameType::IDR;
        else
            trackSegCtxs[tileIdx].codedMeta.type = VCD::MP4::FrameType::NONIDR;

        trackSegCtxs[tileIdx].codedMeta.isEOS = isEOS;

        int32_t ret = dashSegmenter->SegmentData(&(trackSegCtxs[tileIdx]));
        if (ret)
            return ret;

        trackSegCtxs[tileIdx].codedMeta.presIndex++;
        trackSegCtxs[tileIdx].codedMeta.codingIndex++;
        trackSegCtxs[tileIdx].codedMeta.presTime.m_num += 1000;// / (m_frameRate.num / m_frameRate.den);
        //trackSegCtxs[tileIdx].codedMeta.presTime.m_den = 1000;
        //cout << "presTime  " << trackSegCtxs[tileIdx].codedMeta.presTime.m_num << endl;

        m_segNum = dashSegmenter->GetSegmentsNum();

#ifdef _USE_TRACE_
        //trace
        if (m_segNum == (m_prevSegNum + 1))
        {
            uint64_t segSize = dashSegmenter->GetSegmentSize();
            uint32_t trackIndex = trackSegCtxs[tileIdx].trackIdx.GetIndex();
            const char *trackType = "tile_track";
            char tileRes[128] = { 0 };
            snprintf(tileRes, 128, "%d x %d", (trackSegCtxs[tileIdx].tileInfo)->tileWidth, (trackSegCtxs[tileIdx].tileInfo)->tileHeight);

            tracepoint(bandwidth_tp_provider, packed_segment_size, trackIndex, trackType, tileRes, m_segNum, segSize);
        }
#endif
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::WriteSegmentForEachAudio(MediaStream *stream, FrameBSInfo *frameData, bool isKeyFrame, bool isEOS)
{
    if (!stream)
        return OMAF_ERROR_NULL_PTR;

    AudioStream *as = (AudioStream*)stream;

    uint8_t hdrSize = as->GetHeaderDataSize();

    std::map<MediaStream*, TrackSegmentCtx*>::iterator itStreamTrack;
    itStreamTrack = m_streamSegCtx.find(stream);
    if (itStreamTrack == m_streamSegCtx.end())
        return OMAF_ERROR_STREAM_NOT_FOUND;

    TrackSegmentCtx *trackSegCtx = itStreamTrack->second;
    if (!trackSegCtx)
        return OMAF_ERROR_NULL_PTR;

    if (isKeyFrame)
        trackSegCtx->codedMeta.type = VCD::MP4::FrameType::IDR;
    else
        trackSegCtx->codedMeta.type = VCD::MP4::FrameType::NONIDR;

    trackSegCtx->codedMeta.isEOS = isEOS;
    trackSegCtx->isEOS = isEOS;

    if (frameData && frameData->data && frameData->dataSize)
    {
        trackSegCtx->audioNalu.data = frameData->data + hdrSize;
        trackSegCtx->audioNalu.dataSize = frameData->dataSize - hdrSize;
    }
    else
    {
        trackSegCtx->audioNalu.data = NULL;
        trackSegCtx->audioNalu.dataSize = 0;
    }

    DashSegmenter *dashSegmenter = trackSegCtx->dashSegmenter;
    if (!dashSegmenter)
        return OMAF_ERROR_NULL_PTR;

    int32_t ret = dashSegmenter->SegmentData(trackSegCtx);
    if (ret)
        return ret;

    trackSegCtx->codedMeta.presIndex++;
    trackSegCtx->codedMeta.codingIndex++;
    trackSegCtx->codedMeta.presTime.m_num += 1000 / (m_frameRate.num / m_frameRate.den);
    trackSegCtx->codedMeta.presTime.m_den = 1000;

    m_audioSegNum = dashSegmenter->GetSegmentsNum();

    return ERROR_NONE;
}

int32_t DefaultSegmentation::WriteSegmentForEachExtractorTrack(
    ExtractorTrack *extractorTrack,
    bool isKeyFrame,
    bool isEOS)
{
    if (!extractorTrack)
        return OMAF_ERROR_NULL_PTR;

    std::map<ExtractorTrack*, TrackSegmentCtx*>::iterator it;
    it = m_extractorSegCtx.find(extractorTrack);
    if (it == m_extractorSegCtx.end())
        return OMAF_ERROR_EXTRACTORTRACK_NOT_FOUND;

    TrackSegmentCtx *trackSegCtx = it->second;
    if (!trackSegCtx)
        return OMAF_ERROR_NULL_PTR;

    if (isKeyFrame)
        trackSegCtx->codedMeta.type = VCD::MP4::FrameType::IDR;
    else
        trackSegCtx->codedMeta.type = VCD::MP4::FrameType::NONIDR;

    trackSegCtx->codedMeta.isEOS = isEOS;

    DashSegmenter *dashSegmenter = trackSegCtx->dashSegmenter;
    if (!dashSegmenter)
       return OMAF_ERROR_NULL_PTR;

    int32_t ret = dashSegmenter->SegmentData(trackSegCtx);
    if (ret)
        return ret;

    trackSegCtx->codedMeta.presIndex++;
    trackSegCtx->codedMeta.codingIndex++;
    trackSegCtx->codedMeta.presTime.m_num += 1000;// / (m_frameRate.num / m_frameRate.den);
    //trackSegCtx->codedMeta.presTime.m_den = 1000;

#ifdef _USE_TRACE_
    uint64_t currSegNum = dashSegmenter->GetSegmentsNum();
    if (currSegNum == (m_prevSegNum + 1))
    {
        uint64_t segSize = dashSegmenter->GetSegmentSize();
        uint32_t trackIndex = trackSegCtx->trackIdx.GetIndex();
        const char *trackType = "extractor_track";
        char tileRes[128] = { 0 };
        snprintf(tileRes, 128, "%s", "none");

        tracepoint(bandwidth_tp_provider, packed_segment_size, trackIndex, trackType, tileRes, currSegNum, segSize);
    }
#endif

    return ERROR_NONE;
}

int32_t DefaultSegmentation::StartExtractorTrackSegmentation(
    ExtractorTrack *extractorTrack)
{
    pthread_t threadId;
    int32_t ret = pthread_create(&threadId, NULL, ExtractorTrackSegThread, this);

    if (ret)
    {
        return OMAF_ERROR_CREATE_THREAD;
    }

    m_extractorThreadIds.insert(std::make_pair(threadId, extractorTrack));
    return ERROR_NONE;
}

int32_t DefaultSegmentation::StartLastExtractorTrackSegmentation(
    ExtractorTrack *extractorTrack)
{
    pthread_t threadId;
    int32_t ret = pthread_create(&threadId, NULL, LastExtractorTrackSegThread, this);

    if (ret)
    {
        return OMAF_ERROR_CREATE_THREAD;
    }

    m_extractorThreadIds.insert(std::make_pair(threadId, extractorTrack));
    return ERROR_NONE;
}

void *DefaultSegmentation::ExtractorTrackSegThread(void *pThis)
{
    DefaultSegmentation *defaultSegmentation = (DefaultSegmentation*)pThis;

    defaultSegmentation->ExtractorTrackSegmentation();

    return NULL;
}

void *DefaultSegmentation::LastExtractorTrackSegThread(void *pThis)
{
    DefaultSegmentation *defaultSegmentation = (DefaultSegmentation*)pThis;

    defaultSegmentation->LastExtractorTrackSegmentation();

    return NULL;
}

int32_t DefaultSegmentation::ExtractorTrackSegmentation()
{
    bool isFrameReady = false;
    ExtractorTrack *extractorTrack = NULL;
    pthread_t threadId = pthread_self();
    if (threadId == 0)
    {
        return OMAF_ERROR_INVALID_THREAD;
    }

    while(1)
    {
        std::map<pthread_t, ExtractorTrack*>::iterator itETThread;
        itETThread = m_extractorThreadIds.find(threadId);
        if (itETThread != m_extractorThreadIds.end())
        {
            extractorTrack = itETThread->second;
            break;
        }
        usleep(50);
    }

    while(1)
    {

        std::map<uint16_t, ExtractorTrack*> *extractorTracks = m_extractorTrackMan->GetAllExtractorTracks();
        std::map<uint16_t, ExtractorTrack*>::iterator itExtractorTrack;

        for (itExtractorTrack = extractorTracks->begin();
            itExtractorTrack != extractorTracks->end(); itExtractorTrack++)
        {
            if (itExtractorTrack->second == extractorTrack)
                break;
        }
        if (itExtractorTrack == extractorTracks->end())
        {
            return OMAF_ERROR_INVALID_DATA;
        }
        isFrameReady = ((m_currSegedFrmNum == (m_prevSegedFrmNum + 1)) && (extractorTrack->GetProcessedFrmNum() == m_currProcessedFrmNum) && (m_currSegedFrmNum == (m_currProcessedFrmNum + 1)));
        while (!isFrameReady)
        {
            usleep(50);
            isFrameReady = ((m_currSegedFrmNum == (m_prevSegedFrmNum + 1)) && (extractorTrack->GetProcessedFrmNum() == m_currProcessedFrmNum) && (m_currSegedFrmNum == (m_currProcessedFrmNum + 1)));
        }

        uint8_t etId = 0;
        for ( ; etId < m_aveETPerSegThread; etId++)
        {

            if (itExtractorTrack == extractorTracks->end())
            {
                return OMAF_ERROR_INVALID_DATA;
            }

            ExtractorTrack *extractorTrack1 = itExtractorTrack->second;

            extractorTrack1->ConstructExtractors();
            WriteSegmentForEachExtractorTrack(extractorTrack1, m_nowKeyFrame, m_isEOS);

            std::map<ExtractorTrack*, TrackSegmentCtx*>::iterator itET;
            itET = m_extractorSegCtx.find(extractorTrack1);
            if (itET == m_extractorSegCtx.end())
            {
                return OMAF_ERROR_INVALID_DATA;
            }
            TrackSegmentCtx *trackSegCtx = itET->second;

            if (m_segNum == (m_prevSegNum + 1))
            {
                extractorTrack1->DestroyCurrSegNalus();
            }

            if (trackSegCtx->extractorTrackNalu.data)
            {
                extractorTrack1->AddExtractorsNaluToSeg(trackSegCtx->extractorTrackNalu.data);
                trackSegCtx->extractorTrackNalu.data = NULL;
            }
            trackSegCtx->extractorTrackNalu.dataSize = 0;

            extractorTrack1->IncreaseProcessedFrmNum();
            itExtractorTrack++;
        }
        if (m_isEOS)
            break;
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::LastExtractorTrackSegmentation()
{
    bool isFrameReady = false;
    ExtractorTrack *extractorTrack = NULL;
    pthread_t threadId = pthread_self();
    if (threadId == 0)
    {
        return OMAF_ERROR_INVALID_THREAD;
    }

    while(1)
    {
        std::map<pthread_t, ExtractorTrack*>::iterator itETThread;
        itETThread = m_extractorThreadIds.find(threadId);
        if (itETThread != m_extractorThreadIds.end())
        {
            extractorTrack = itETThread->second;
            break;
        }
        usleep(50);
    }

    while(1)
    {
        std::map<uint16_t, ExtractorTrack*> *extractorTracks = m_extractorTrackMan->GetAllExtractorTracks();
        std::map<uint16_t, ExtractorTrack*>::iterator itExtractorTrack;

        for (itExtractorTrack = extractorTracks->begin();
            itExtractorTrack != extractorTracks->end(); itExtractorTrack++)
        {
            if (itExtractorTrack->second == extractorTrack)
                break;
        }
        if (itExtractorTrack == extractorTracks->end())
        {
            return OMAF_ERROR_INVALID_DATA;
        }

        isFrameReady = ((m_currSegedFrmNum == (m_prevSegedFrmNum + 1)) && (extractorTrack->GetProcessedFrmNum() == m_currProcessedFrmNum) && (m_currSegedFrmNum == (m_currProcessedFrmNum + 1)));
        while (!isFrameReady)
        {
            usleep(50);
            isFrameReady = ((m_currSegedFrmNum == (m_prevSegedFrmNum + 1)) && (extractorTrack->GetProcessedFrmNum() == m_currProcessedFrmNum) && (m_currSegedFrmNum == (m_currProcessedFrmNum + 1)));
        }

        uint8_t etId = 0;
        for ( ; etId < m_lastETPerSegThread; etId++)
        {

            if (itExtractorTrack == extractorTracks->end())
            {
                return OMAF_ERROR_INVALID_DATA;
            }

            ExtractorTrack *extractorTrack1 = itExtractorTrack->second;
            extractorTrack1->ConstructExtractors();
            WriteSegmentForEachExtractorTrack(extractorTrack1, m_nowKeyFrame, m_isEOS);

            std::map<ExtractorTrack*, TrackSegmentCtx*>::iterator itET;
            itET = m_extractorSegCtx.find(extractorTrack1);
            if (itET == m_extractorSegCtx.end())
            {
                return OMAF_ERROR_INVALID_DATA;
            }
            TrackSegmentCtx *trackSegCtx = itET->second;

            if (m_segNum == (m_prevSegNum + 1))
            {
                extractorTrack1->DestroyCurrSegNalus();
            }

            if (trackSegCtx->extractorTrackNalu.data)
            {
                extractorTrack1->AddExtractorsNaluToSeg(trackSegCtx->extractorTrackNalu.data);
                trackSegCtx->extractorTrackNalu.data = NULL;
            }
            trackSegCtx->extractorTrackNalu.dataSize = 0;

            extractorTrack1->IncreaseProcessedFrmNum();
            itExtractorTrack++;
        }
        if (m_isEOS)
            break;
    }

    return ERROR_NONE;
}

bool DefaultSegmentation::HasAudio()
{
    std::map<uint8_t, MediaStream*>::iterator it;
    for (it = m_streamMap->begin(); it != m_streamMap->end(); it++)
    {
        MediaStream *stream = it->second;
        if (stream && (stream->GetMediaType() == AUDIOTYPE))
        {
            return true;
        }
    }

    return false;
}

bool DefaultSegmentation::OnlyAudio()
{
    std::map<uint8_t, MediaStream*>::iterator it;
    for (it = m_streamMap->begin(); it != m_streamMap->end(); it++)
    {
        MediaStream *stream = it->second;
        if (stream && (stream->GetMediaType() == VIDEOTYPE))
        {
            return false;
        }
    }

    return true;
}

int32_t DefaultSegmentation::VideoSegmentation()
{
    uint64_t currentT = 0;
    int32_t ret = ConstructTileTrackSegCtx();
    if (ret)
        return ret;

    ret = ConstructExtractorTrackSegCtx();
    if (ret)
        return ret;

    bool hasAudio = HasAudio();
    if (hasAudio)
    {
        uint32_t waitTimes = 10000;
        uint32_t currWaitTime = 0;
        while (currWaitTime < waitTimes)
        {
            {
                std::lock_guard<std::mutex> lock(m_audioMutex);
                if (m_audioSegCtxsConsted)
                {
                    break;
                }
            }
            usleep(50);
            currWaitTime++;
        }
        if (currWaitTime >= waitTimes)
        {
            return OMAF_ERROR_TIMED_OUT;
        }

        {
            std::lock_guard<std::mutex> lock(m_audioMutex);
            /*
            m_mpdGen = new MpdGenerator(
                        &m_streamSegCtx,
                        &m_extractorSegCtx,
                        m_segInfo,
                        m_projType,
                        m_frameRate,
                        m_videosNum,
                        m_isCMAFEnabled);
            if (!m_mpdGen)
                return OMAF_ERROR_NULL_PTR;
            */
            ret = CreateDashMPDWriter();
            if (ret)
                return ret;

            ret = m_mpdWriter->Initialize();

            if (ret)
                return ret;

            m_isMpdGenInit = true;
        }
    }
    else
    {
        /*
        m_mpdGen = new MpdGenerator(
                        &m_streamSegCtx,
                        &m_extractorSegCtx,
                        m_segInfo,
                        m_projType,
                        m_frameRate,
                        m_videosNum,
                        m_isCMAFEnabled);
        if (!m_mpdGen)
            return OMAF_ERROR_NULL_PTR;
        */
        ret = CreateDashMPDWriter();
        if (ret)
            return ret;

        ret = m_mpdWriter->Initialize();

        if (ret)
            return ret;

        m_isMpdGenInit = true;
    }

    std::map<MediaStream*, TrackSegmentCtx*>::iterator itStreamTrack;
    for (itStreamTrack = m_streamSegCtx.begin(); itStreamTrack != m_streamSegCtx.end(); itStreamTrack++)
    {
        MediaStream *stream = itStreamTrack->first;
        TrackSegmentCtx* trackSegCtxs = itStreamTrack->second;

        if (stream->GetMediaType() == VIDEOTYPE)
        {
            VideoStream *vs = (VideoStream*)stream;
            uint32_t tilesNum = vs->GetTileInRow() * vs->GetTileInCol();
            for (uint32_t tileIdx = 0; tileIdx < tilesNum; tileIdx++)
            {
                DashInitSegmenter *initSegmenter = trackSegCtxs[tileIdx].initSegmenter;
                if (!initSegmenter)
                    return OMAF_ERROR_NULL_PTR;

                ret = initSegmenter->GenerateInitSegment(&(trackSegCtxs[tileIdx]), m_trackSegCtx);
                if (ret)
                    return ret;

#ifdef _USE_TRACE_
                //trace
                uint64_t initSegSize = initSegmenter->GetInitSegmentSize();
                uint32_t trackIndex  = trackSegCtxs[tileIdx].trackIdx.GetIndex();
                const char *trackType = "init_track";
                char tileRes[128] = { 0 };
                snprintf(tileRes, 128, "%s", "none");

                tracepoint(bandwidth_tp_provider, packed_segment_size,
                            trackIndex, trackType, tileRes, 0, initSegSize);
#endif
            }
        }
    }

    if (m_extractorSegCtx.size())
    {
        std::map<ExtractorTrack*, TrackSegmentCtx*>::iterator itExtractorTrack;
        for (itExtractorTrack = m_extractorSegCtx.begin();
            itExtractorTrack != m_extractorSegCtx.end();
            itExtractorTrack++)
        {
            TrackSegmentCtx *trackSegCtx =  itExtractorTrack->second;

            DashInitSegmenter *initSegmenter = trackSegCtx->initSegmenter;
            if (!initSegmenter)
                return OMAF_ERROR_NULL_PTR;

            ret = initSegmenter->GenerateInitSegment(trackSegCtx, m_trackSegCtx);
            if (ret)
                return ret;

#ifdef _USE_TRACE_
            //trace
            uint64_t initSegSize = initSegmenter->GetInitSegmentSize();
            uint32_t trackIndex  = trackSegCtx->trackIdx.GetIndex();
            const char *trackType = "init_track";
            char tileRes[128] = { 0 };
            snprintf(tileRes, 128, "%s", "none");

            tracepoint(bandwidth_tp_provider, packed_segment_size,
                        trackIndex, trackType, tileRes, 0, initSegSize);
#endif
        }
    }
    m_prevSegNum = m_segNum;

    uint16_t extractorTrackNum = m_extractorSegCtx.size();
    if (extractorTrackNum)
    {
        if (extractorTrackNum % m_segInfo->extractorTracksPerSegThread == 0)
        {
            m_aveETPerSegThread = m_segInfo->extractorTracksPerSegThread;
            m_lastETPerSegThread = m_segInfo->extractorTracksPerSegThread;
            m_threadNumForET = extractorTrackNum / m_segInfo->extractorTracksPerSegThread;
        }
        else
        {
            m_aveETPerSegThread = m_segInfo->extractorTracksPerSegThread;
            m_lastETPerSegThread = extractorTrackNum % m_segInfo->extractorTracksPerSegThread;
            m_threadNumForET = extractorTrackNum / m_segInfo->extractorTracksPerSegThread + 1;
        }

    }

#ifdef _USE_TRACE_
    int64_t trackIdxTag = 0;
#endif

    while (1)
    {
        if (m_segNum == 1)
        {
            if (hasAudio)
            {
                uint32_t waitTimes = 50000;
                uint32_t currWaitTime = 0;
                while (currWaitTime < waitTimes)
                {
                    {
                        std::lock_guard<std::mutex> lock(m_audioMutex);
                        if (m_audioSegNum >= 1)
                        {
                            break;
                        }
                    }
                    usleep(50);
                    currWaitTime++;
                }
                if (currWaitTime >= waitTimes)
                {
                    return OMAF_ERROR_TIMED_OUT;
                }
            }

            if (m_segInfo->isLive)
            {
                m_mpdWriter->UpdateMpd(m_segNum, m_framesNum);
            }
        }

        std::map<uint8_t, MediaStream*>::iterator itStream = m_streamMap->begin();
        for ( ; itStream != m_streamMap->end(); itStream++)
        {
            MediaStream *stream = itStream->second;
            if (stream->GetMediaType() == VIDEOTYPE)
            {
                VideoStream *vs = (VideoStream*)stream;
                vs->SetCurrFrameInfo();
                FrameBSInfo *currFrame = vs->GetCurrFrameInfo();

                while (!currFrame)
                {
                    usleep(50);
                    vs->SetCurrFrameInfo();
                    currFrame = vs->GetCurrFrameInfo();
                    if (!currFrame && (vs->GetEOS()))
                        break;
                }

                if (currFrame)
                {
                    m_framesIsKey[vs] = currFrame->isKeyFrame;
                    m_streamsIsEOS[vs] = false;

#ifdef _USE_TRACE_
                    //trace
                    char resolution[1024] = { 0 };
                    snprintf(resolution, 1024, "%d x %d", vs->GetSrcWidth(), vs->GetSrcHeight());
                    char tileSplit[1024] = { 0 };
                    snprintf(tileSplit, 1024, "%d x %d", vs->GetTileInCol(), vs->GetTileInRow());
                    tracepoint(bandwidth_tp_provider, encoded_frame_size,
                                &resolution[0], &tileSplit[0], m_framesNum, currFrame->dataSize);
#endif

                    vs->UpdateTilesNalu();
                    WriteSegmentForEachVideo(vs, currFrame->isKeyFrame, false);
                }
                else
                {
                    m_framesIsKey[vs] = false;
                    m_streamsIsEOS[vs] = true;

                    WriteSegmentForEachVideo(vs, false, true);
                }
            }
        }

        std::map<MediaStream*, bool>::iterator itKeyFrame = m_framesIsKey.begin();
        if (itKeyFrame == m_framesIsKey.end())
            return OMAF_ERROR_INVALID_DATA;
        bool frameIsKey = itKeyFrame->second;
        itKeyFrame++;
        for ( ; itKeyFrame != m_framesIsKey.end(); itKeyFrame++)
        {
            bool keyFrame = itKeyFrame->second;
            if (frameIsKey != keyFrame)
                return OMAF_ERROR_INVALID_DATA;
        }
        m_nowKeyFrame = frameIsKey;

        std::map<MediaStream*, bool>::iterator itEOS = m_streamsIsEOS.begin();
        if (itEOS == m_streamsIsEOS.end())
            return OMAF_ERROR_STREAM_NOT_FOUND;
        bool nowEOS = itEOS->second;
        itEOS++;
        for ( ; itEOS != m_streamsIsEOS.end(); itEOS++)
        {
            bool eos = itEOS->second;
            if (nowEOS != eos)
                return OMAF_ERROR_INVALID_DATA;
        }
        m_isEOS = nowEOS;

        m_currSegedFrmNum++;

        std::map<uint16_t, ExtractorTrack*> *extractorTracks = m_extractorTrackMan->GetAllExtractorTracks();
        if (extractorTracks->size())
        {
            std::map<uint16_t, ExtractorTrack*>::iterator itExtractorTrack = extractorTracks->begin();
            for ( ; itExtractorTrack != extractorTracks->end(); /*itExtractorTrack++*/)
            {
                ExtractorTrack *extractorTrack = itExtractorTrack->second;
                if (m_extractorThreadIds.size() < m_threadNumForET)
                {
                    if (m_aveETPerSegThread == m_lastETPerSegThread)
                    {
                        int32_t retET = StartExtractorTrackSegmentation(extractorTrack);
                        if (retET)
                            return retET;

                        for (uint16_t num = 0; num < m_aveETPerSegThread; num++)
                        {
                            if (itExtractorTrack != extractorTracks->end())
                            {
                                itExtractorTrack++;
                            }
                        }
                    }
                    else
                    {
                        if ((uint16_t)(m_extractorThreadIds.size()) < (m_threadNumForET - 1))
                        {
                            int32_t retET = StartExtractorTrackSegmentation(extractorTrack);
                            if (retET)
                                return retET;

                            for (uint16_t num = 0; num < m_aveETPerSegThread; num++)
                            {
                                if (itExtractorTrack != extractorTracks->end())
                                {
                                    itExtractorTrack++;
                                }
                            }
                        }
                        else
                        {
                            int32_t retET = StartLastExtractorTrackSegmentation(extractorTrack);
                            if (retET)
                                return retET;

                            for ( ; itExtractorTrack != extractorTracks->end(); )
                            {
                                itExtractorTrack++;
                            }
                        }
                    }
                }
                else
                {
                    break;
                }
            }
            if (m_extractorThreadIds.size() != m_threadNumForET)
            {
            }

            usleep(2000);

            for (itExtractorTrack = extractorTracks->begin();
                itExtractorTrack != extractorTracks->end();
                itExtractorTrack++)
            {
                ExtractorTrack *extractorTrack = itExtractorTrack->second;
                while (extractorTrack->GetProcessedFrmNum() == m_framesNum)
                {
                    usleep(1);

                    if (extractorTrack->GetProcessedFrmNum() == (m_framesNum + 1))
                    {
                        break;
                    }
                }
            }
        }

        m_prevSegedFrmNum++;
        m_currProcessedFrmNum++;

        for (itStream = m_streamMap->begin(); itStream != m_streamMap->end(); itStream++)
        {
            MediaStream *stream = itStream->second;
            if (stream->GetMediaType() == VIDEOTYPE)
            {
                VideoStream *vs = (VideoStream*)stream;

                if (m_segNum == (m_prevSegNum + 1))
                {
                    vs->DestroyCurrSegmentFrames();
                }

                vs->AddFrameToSegment();
            }
        }

        if (m_segNum == (m_prevSegNum + 1))
        {
            m_prevSegNum++;

            std::chrono::high_resolution_clock clock;
            uint64_t before = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
            currentT = before;
            if (m_isCMAFEnabled && m_segInfo->isLive)
            {
                m_mpdWriter->UpdateMpd(m_segNum, m_framesNum);
            }

        }

        if (m_segInfo->isLive)
        {
            if (m_segInfo->windowSize && m_segInfo->extraWindowSize)
            {
                int32_t removeCnt = m_segNum - m_segInfo->windowSize - m_segInfo->extraWindowSize;
                if (removeCnt > 0)
                {
                    std::map<VCD::MP4::TrackId, TrackConfig>::iterator itOneTrack;
#ifdef _USE_TRACE_
                    auto itOneTrackTag = m_allTileTracks.begin();
                    trackIdxTag = itOneTrackTag->first.GetIndex();
#endif

                    for (itOneTrack = m_allTileTracks.begin();
                        itOneTrack != m_allTileTracks.end();
                        itOneTrack++)
                    {
                        VCD::MP4::TrackId trackIndex = itOneTrack->first;
                        char rmFile[1024];
                        snprintf(rmFile, 1024, "%s%s_track%d.%d.mp4", m_segInfo->dirName, m_segInfo->outName, trackIndex.GetIndex(), removeCnt);
                        remove(rmFile);
                    }
                    if (m_extractorSegCtx.size())
                    {
                        std::map<ExtractorTrack*, TrackSegmentCtx*>::iterator itOneExtractorTrack;
                        for (itOneExtractorTrack = m_extractorSegCtx.begin();
                            itOneExtractorTrack != m_extractorSegCtx.end();
                            itOneExtractorTrack++)
                        {
                            TrackSegmentCtx *trackSegCtx = itOneExtractorTrack->second;
                            VCD::MP4::TrackId trackIndex = trackSegCtx->trackIdx;
                            char rmFile[1024];
                            snprintf(rmFile, 1024, "%s%s_track%d.%d.mp4", m_segInfo->dirName, m_segInfo->outName, trackIndex.GetIndex(), removeCnt);
                            remove(rmFile);
                        }
                    }
                }
            }
        }

        if (m_isEOS)
        {
            if (m_segInfo->isLive)
            {
                if (hasAudio)
                {
                    uint32_t waitTimes = 10000;
                    uint32_t currWaitTime = 0;
                    while (currWaitTime < waitTimes)
                    {
                        {
                            std::lock_guard<std::mutex> lock(m_audioMutex);
                            if (m_audioSegNum >= m_segNum)
                            {
                                break;
                            }
                        }
                        usleep(50);
                        currWaitTime++;
                    }
                    if (currWaitTime >= waitTimes)
                    {
                        return OMAF_ERROR_TIMED_OUT;
                    }
                }
                int32_t ret = m_mpdWriter->UpdateMpd(m_segNum, m_framesNum);
                if (ret)
                    return ret;
            } else {
#ifdef _USE_TRACE_
                //trace
                const char *dashMode = "static";
                float currFrameRate = (float)(m_frameRate.num) / (float)(m_frameRate.den);
                tracepoint(bandwidth_tp_provider, segmentation_info,
                    dashMode, m_segInfo->segDuration, currFrameRate,
                    m_videosNum, m_videosBitrate,
                    m_framesNum, m_segNum);
#endif

                if (hasAudio)
                {
                    uint32_t waitTimes = 10000;
                    uint32_t currWaitTime = 0;
                    while (currWaitTime < waitTimes)
                    {
                        {
                            std::lock_guard<std::mutex> lock(m_audioMutex);
                            if (m_audioSegNum >= m_segNum)
                            {
                                break;
                            }
                        }
                        usleep(50);
                        currWaitTime++;
                    }
                    if (currWaitTime >= waitTimes)
                    {
                        return OMAF_ERROR_TIMED_OUT;
                    }
                }

                int32_t ret = m_mpdWriter->WriteMpd(m_framesNum);
                if (ret)
                    return ret;
            }
            break;
        }
#ifdef _USE_TRACE_
        string tag = "trackIdx:" + to_string(trackIdxTag);
        tracepoint(E2E_latency_tp_provider,
                   post_op_info,
                   m_framesNum,
                   tag.c_str());
#endif
        m_framesNum++;
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::AudioSegmentation()
{
    uint64_t currentT = 0;
    int32_t ret = ConstructAudioTrackSegCtx();
    if (ret)
        return ret;
    bool onlyAudio = OnlyAudio();
    if (onlyAudio)
    {
        /*
        m_mpdGen = new MpdGenerator(
                        &m_streamSegCtx,
                        &m_extractorSegCtx,
                        m_segInfo,
                        m_projType,
                        m_frameRate,
                        0,
                        m_isCMAFEnabled);
        if (!m_mpdGen)
            return OMAF_ERROR_NULL_PTR;
        */

        ret = CreateDashMPDWriter();
        if (ret)
            return ret;

        ret = m_mpdWriter->Initialize();

        if (ret)
            return ret;

        m_isMpdGenInit = true;
    }
    else
    {
        bool mpdGenInitialized = false;
        while(!mpdGenInitialized)
        {
            {
                std::lock_guard<std::mutex> lock(m_audioMutex);
                if (m_isMpdGenInit)
                {
                    mpdGenInitialized = true;
                    break;
                }
            }

            usleep(50);
        }
    }

    std::map<MediaStream*, TrackSegmentCtx*>::iterator itStreamTrack;
    for (itStreamTrack = m_streamSegCtx.begin(); itStreamTrack != m_streamSegCtx.end(); itStreamTrack++)
    {
        MediaStream *stream = itStreamTrack->first;
        TrackSegmentCtx* trackSegCtx = itStreamTrack->second;

        if (stream->GetMediaType() == AUDIOTYPE)
        {
            DashInitSegmenter *initSegmenter = trackSegCtx->initSegmenter;
            if (!initSegmenter)
                return OMAF_ERROR_NULL_PTR;

            ret = initSegmenter->GenerateInitSegment(trackSegCtx, m_trackSegCtx);
            if (ret)
                return ret;

        }
    }

    m_audioPrevSegNum = m_audioSegNum;

    bool nowEOS = false;
    bool eosWritten = false;
    uint64_t framesWritten = 0;
    while(1)
    {
        if (onlyAudio)
        {
            if (m_audioSegNum == 1)
            {
                if (m_segInfo->isLive)
                {
                    m_mpdWriter->UpdateMpd(m_audioSegNum, m_framesNum);
                }
            }
        }

        std::map<uint8_t, MediaStream*>::iterator itStream = m_streamMap->begin();
        for ( ; itStream != m_streamMap->end(); itStream++)
        {
            MediaStream *stream = itStream->second;
            if (stream && (stream->GetMediaType() == AUDIOTYPE))
            {
                AudioStream *as = (AudioStream*)stream;
                as->SetCurrFrameInfo();
                FrameBSInfo *currFrame = as->GetCurrFrameInfo();

                while (!currFrame)
                {
                    usleep(50);
                    as->SetCurrFrameInfo();
                    currFrame = as->GetCurrFrameInfo();
                    if (!currFrame && (as->GetEOS()))
                        break;
                }
                nowEOS = as->GetEOS();
                if (currFrame)
                {
                    WriteSegmentForEachAudio(as, currFrame, true, false);
                    framesWritten++;
                }
                else
                {
                    eosWritten = true;
                }
            }
        }

        for (itStream = m_streamMap->begin(); itStream != m_streamMap->end(); itStream++)
        {
            MediaStream *stream = itStream->second;
            if (stream && (stream->GetMediaType() == AUDIOTYPE))
            {
                AudioStream *as = (AudioStream*)stream;

                if (m_audioSegNum == (m_audioPrevSegNum + 1))
                {
                    as->DestroyCurrSegmentFrames();
                }

                as->AddFrameToSegment();
            }
        }

        if (m_audioSegNum == (m_audioPrevSegNum + 1))
        {
            m_audioPrevSegNum++;

            std::chrono::high_resolution_clock clock;
            uint64_t before = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
            currentT = before;
        }

        if (m_segInfo->isLive)
        {
            if (m_segInfo->windowSize && m_segInfo->extraWindowSize)
            {
                int32_t removeCnt = m_audioSegNum - m_segInfo->windowSize - m_segInfo->extraWindowSize;
                if (removeCnt > 0)
                {
                    for (itStream = m_streamMap->begin(); itStream != m_streamMap->end(); itStream++)
                    {
                        MediaStream *stream = itStream->second;
                        if (stream && (stream->GetMediaType() == AUDIOTYPE))
                        {
                            TrackSegmentCtx* oneSegCtx = m_streamSegCtx[stream];
                            if (!oneSegCtx)
                                return OMAF_ERROR_NULL_PTR;

                            VCD::MP4::TrackId trackIndex = oneSegCtx->trackIdx;
                            char rmFile[1024];
                            snprintf(rmFile, 1024, "%s%s_track%d.%d.mp4", m_segInfo->dirName, m_segInfo->outName, trackIndex.GetIndex(), removeCnt);
                            remove(rmFile);
                        }
                    }
                }
            }
        }

        if (onlyAudio)
        {
            if (nowEOS && eosWritten)
            {
                if (m_segInfo->isLive)
                {
                    int32_t ret = m_mpdWriter->UpdateMpd(m_audioSegNum, m_framesNum);
                    if (ret)
                        return ret;
                } else {
                    int32_t ret = m_mpdWriter->WriteMpd(m_framesNum);
                    if (ret)
                        return ret;
                }
                break;
            }
            m_framesNum++;
        }

        if (nowEOS && eosWritten)
        {
            std::map<uint8_t, MediaStream*>::iterator itStr = m_streamMap->begin();
            for ( ; itStr != m_streamMap->end(); itStr++)
            {
                MediaStream *stream = itStr->second;
                if (stream && (stream->GetMediaType() == AUDIOTYPE))
                {
                    AudioStream *as = (AudioStream*)stream;
                    WriteSegmentForEachAudio(as, NULL, false, true);
                }
            }

            break;
        }
    }

    return ERROR_NONE;
}

int32_t DefaultSegmentation::EndEachVideo(MediaStream *stream)
{
    if (!stream)
        return OMAF_ERROR_NULL_PTR;

    VideoStream *vs = (VideoStream*)stream;
    vs->SetEOS(true);

    return ERROR_NONE;
}

int32_t DefaultSegmentation::EndEachAudio(MediaStream *stream)
{
    if (!stream)
        return OMAF_ERROR_NULL_PTR;

    AudioStream *as = (AudioStream*)stream;
    as->SetEOS(true);

    return ERROR_NONE;
}

VCD_NS_END
