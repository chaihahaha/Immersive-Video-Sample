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
//! \file     CubeMapRenderTarget.cpp
//! \brief    Implement class for cube map RenderTarget.
//!

#include "CubeMapRenderTarget.h"
#include "RenderContext.h"
#ifdef _LINUX_OS_
#include <GL/glu.h>
//#include <GL/glu_mangle.h>
#include <GL/gl.h>
//#include <GL/glx.h>
//#include <GL/glext.h>
//#include <GL/glcorearb.h>
#endif
#ifdef _ANDROID_OS_
#include <GLES3/gl3.h>
#include <GLES3/gl3ext.h>
#include <GLES3/gl3platform.h>
#endif
#include <algorithm>
#include <iostream>
#include <chrono>
#ifndef _ANDROID_OS_
#ifdef _USE_TRACE_
#include "../../../trace/MtHQ_tp.h"
#endif
#endif
#include "../Common/RegionData.h"
#include "../Common/DataLog.h"

#define CUBE_MAP_ROW 2
#define CUBE_MAP_COL 3


VCD_NS_BEGIN

CubeMapRenderTarget::CubeMapRenderTarget()
{// first in pair is face x in OMAF * second in pair is face order in GL.
    mOMAF2GLFaceIDMap.clear();
    mOMAF2GLFaceIDMap.insert(make_pair(0, CUBE_MAP_LEFT));
    mOMAF2GLFaceIDMap.insert(make_pair(1, CUBE_MAP_FRONT));
    mOMAF2GLFaceIDMap.insert(make_pair(2, CUBE_MAP_RIGHT));
    mOMAF2GLFaceIDMap.insert(make_pair(3, CUBE_MAP_BOTTOM));
    mOMAF2GLFaceIDMap.insert(make_pair(4, CUBE_MAP_BACK));
    mOMAF2GLFaceIDMap.insert(make_pair(5, CUBE_MAP_TOP));
}

CubeMapRenderTarget::~CubeMapRenderTarget()
{
    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    renderBackend->DeleteFramebuffers(1, &m_fboOnScreenHandle);
    renderBackend->DeleteTextures(1, m_textureOfR2S);
    std::cout<<"AVG CHANGED TIME COST : "<<m_avgChangedTime<<"ms"<<std::endl;
}

RenderStatus CubeMapRenderTarget::Initialize(RenderSourceFactory* rsFactory)
{
    this->m_rsFactory = rsFactory;

    return RENDER_STATUS_OK;
}

RenderStatus CubeMapRenderTarget::CreateRenderTarget()
{
    if(NULL==this->m_rsFactory){
        return RENDER_NULL_HANDLE;
    }

    int32_t width = m_rsFactory->GetSourceResolution()[0].width / CUBE_MAP_COL;// face width
    int32_t height = m_rsFactory->GetSourceResolution()[0].height / CUBE_MAP_ROW; // face height // width and height need to be identical

    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    // 1.generate FBO on screen
    renderBackend->GenFramebuffers(1, &m_fboOnScreenHandle);
    renderBackend->BindFramebuffer(GL_FRAMEBUFFER, m_fboOnScreenHandle);
    // 2.generate CUBE map texture
    renderBackend->GenTextures(1, m_textureOfR2S);
    renderBackend->BindTexture(GL_TEXTURE_CUBE_MAP, m_textureOfR2S[0]);
    for (uint32_t i=0; i<FACE_SIZE; i++)
    {
        renderBackend->TexImage2D(GL_TEXTURE_CUBE_MAP_POSITIVE_X + i, 0, GL_RGB, width, height, 0, GL_RGB, GL_UNSIGNED_BYTE, NULL);
    }
    renderBackend->PixelStorei(GL_UNPACK_ROW_LENGTH, width);
    renderBackend->TexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    renderBackend->TexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    renderBackend->TexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_WRAP_R, GL_CLAMP_TO_EDGE);
    renderBackend->TexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    renderBackend->TexParameteri(GL_TEXTURE_CUBE_MAP, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    return RENDER_STATUS_OK;
}

RenderStatus CubeMapRenderTarget::Update( HeadPose* pose, float hFOV, float vFOV, uint64_t pts )
{
    if(NULL==this->m_rsFactory){
        return  RENDER_NULL_HANDLE;
    }

    RenderBackend *renderBackend = RENDERBACKEND::GetInstance();
    RenderStatus ret = RENDER_STATUS_OK;

    //1 calculate quality ranking information
    ret = CalcQualityRanking();
    if(RENDER_STATUS_OK != ret) return ret;

    //2 get high and low tile id and regionInfoTransfer.
    std::map<int32_t, std::vector<TileInformation>> regionInfoTransfer;
    ret = GetRenderMultiSource(regionInfoTransfer);
    if(RENDER_STATUS_OK != ret) return ret;

    std::vector<uint32_t> TilesInViewport;
    std::chrono::high_resolution_clock clock;

    std::map<uint32_t, RenderSource*> mapRenderSources = m_rsFactory->GetRenderSources();
    //get effective best quality area
    //FIXME: need to get main video_id and main source from packing. so far, video_id:0 with source:0 is the one.
    // RegionInfo *regionInfo = mapRenderSources[0]->GetCurrentRegionInfo();
    uint32_t highRow = m_rsFactory->GetHighTileRow();
    uint32_t highCol = m_rsFactory->GetHighTileCol();
    GetTilesInViewport(pose->yaw, pose->pitch, hFOV, vFOV, highRow, highCol, TilesInViewport);

    /// judge whether all best quality tiles has coverd the current viewport.
    bool isAllHighFlag = true;
    static uint64_t start = 0;
    static uint64_t totalChangedTime = 0;
    static uint32_t changedCount = 0;
    for (uint32_t i = 0; i < TilesInViewport.size(); i++)
    {
        std::vector<TileInformation> listBest = mQualityRankingInfo.mapQualitySelection[mQualityRankingInfo.mainQualityRanking];
        if (!findTileID(listBest, TilesInViewport[i]))//(find(listBest.begin(), listBest.end(), TilesInViewport[i]) == listBest.end())
        {
            isAllHighFlag = false;
            if (m_isAllHighQualityInView) // firt time to be blur
            {
                start = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
#ifndef _ANDROID_OS_
#ifdef _USE_TRACE_
                //trace
                tracepoint(mthq_tp_provider, T0_change_to_lowQ, changedCount+1, pts);
#endif
#endif
            }
            break;
        }
    }
    if (isAllHighFlag && !m_isAllHighQualityInView) // first time to be clear
    {
        uint64_t end = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now().time_since_epoch()).count();
#ifndef _ANDROID_OS_
#ifdef _USE_TRACE_
        //trace
        tracepoint(mthq_tp_provider, T12_change_to_highQ, changedCount+1, pts);
#endif
#endif

        totalChangedTime += end - start;
        changedCount++;
        m_avgChangedTime = (float)totalChangedTime / changedCount;

    }
    m_isAllHighQualityInView = isAllHighFlag;

    /// blit from render source to render target
    renderBackend->BindFramebuffer(GL_DRAW_FRAMEBUFFER, m_fboOnScreenHandle);
    renderBackend->Clear(GL_COLOR_BUFFER_BIT);//clear buffer.
    //get render source through video_id which the tile is belongs to.
    for(auto it=mQualityRankingInfo.mapQualitySelection.begin(); it!=mQualityRankingInfo.mapQualitySelection.end(); it++){
        //render low quality first
        std::vector<TileInformation> vec_tile = it->second;
        if(it->first != mQualityRankingInfo.mainQualityRanking){
            for(auto itq=vec_tile.begin(); itq!=vec_tile.end(); itq++){
                TileInformation ti = *itq;
                RenderSource* rs = mapRenderSources[ti.video_id];
                renderBackend->BindFramebuffer(GL_READ_FRAMEBUFFER, rs->GetFboR2THandle());
                glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_CUBE_MAP_POSITIVE_X + ti.face_id, m_textureOfR2S[0], 0);
                glBlitFramebuffer( ti.packedRegLeft,
                                   ti.packedRegTop,
                                   ti.packedRegLeft + ti.packedRegWidth,
                                   ti.packedRegTop + ti.packedRegHeight,
                                   ti.projRegLeft,
                                   ti.projRegTop,
                                   ti.projRegLeft + ti.projRegWidth,
                                   ti.projRegTop + ti.projRegHeight,
                                   GL_COLOR_BUFFER_BIT, GL_NEAREST);
                renderBackend->BindFramebuffer(GL_READ_FRAMEBUFFER, 0);
            }
        }
    }

    std::vector<TileInformation> vec_main = mQualityRankingInfo.mapQualitySelection[mQualityRankingInfo.mainQualityRanking];
    for(auto itm=vec_main.begin(); itm!=vec_main.end(); itm++){
        TileInformation ti = *itm;
        RenderSource* rs = mapRenderSources[ti.video_id];
        renderBackend->BindFramebuffer(GL_READ_FRAMEBUFFER, rs->GetFboR2THandle());
        glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_CUBE_MAP_POSITIVE_X + ti.face_id, m_textureOfR2S[0], 0);
        glBlitFramebuffer( ti.packedRegLeft,
                           ti.packedRegTop,
                           ti.packedRegLeft + ti.packedRegWidth,
                           ti.packedRegTop + ti.packedRegHeight,
                           ti.projRegLeft,
                           ti.projRegTop,
                           ti.projRegLeft + ti.projRegWidth,
                           ti.projRegTop + ti.projRegHeight,
                           GL_COLOR_BUFFER_BIT, GL_NEAREST);
        renderBackend->BindFramebuffer(GL_READ_FRAMEBUFFER, 0);
    }

    return RENDER_STATUS_OK;
}

RenderStatus CubeMapRenderTarget::UpdateDisplayTex()
{
    return RENDER_STATUS_OK;
}

bool CubeMapRenderTarget::findTileID(std::vector<TileInformation> vecTile, uint32_t tile_id)
{
    for(auto it=vecTile.begin(); it!=vecTile.end(); it++){
        if(it->tile_id == tile_id) return true;
    }

    return false;
}

RenderStatus CubeMapRenderTarget::CalcQualityRanking()
{
    if(NULL==this->m_rsFactory){
        return  RENDER_NULL_HANDLE;
    }

    RenderStatus ret = RENDER_STATUS_OK;
    std::map<uint32_t, RenderSource*> mapRenderSources = m_rsFactory->GetRenderSources();
    std::list<int32_t> listQuality;
    uint32_t errorCnt = 0;
    for(auto it=mapRenderSources.begin(); it!=mapRenderSources.end(); it++){
        RegionData *regionInfo = it->second->GetCurrentRegionInfo();
        if (regionInfo == NULL || regionInfo->GetRegionWisePacking() == NULL \
             || regionInfo->GetSourceInfo() == NULL || regionInfo->GetSourceInRegion() > 2)
        {
            errorCnt++;
            continue;
        }
        for(int32_t i=0; i<regionInfo->GetSourceInRegion(); i++)
            listQuality.push_back(regionInfo->GetSourceInfo()[i].qualityRanking);
    }
    if (errorCnt == mapRenderSources.size())
    {
        return RENDER_ERROR;
    }
    listQuality.sort();
    listQuality.unique();

    /// always think the high quality is with smallest quality ranking value;
    mQualityRankingInfo.mainQualityRanking = listQuality.front();
    mQualityRankingInfo.numQuality = listQuality.size();
    mQualityRankingInfo.mapQualitySelection.clear();
    std::vector<TileInformation> TileIDs[mQualityRankingInfo.numQuality];
    int i = 0;
    for(auto it=listQuality.begin(); it!=listQuality.end();it++){
        mQualityRankingInfo.mapQualitySelection[*it]=TileIDs[i];
        i++;
    }

    return RENDER_STATUS_OK;
}

int32_t CubeMapRenderTarget::findQuality(RegionData *regionInfo, RectangularRegionWisePacking rectRWP, int32_t& source_idx)
{
    //get the quality ranking and source index based on tile's RectangularRegionWisePacking through the tile position in the packed source.
    for(int32_t i=0; i<regionInfo->GetSourceInRegion(); i++){
        if(  (rectRWP.packedRegLeft >= regionInfo->GetSourceInfo()[i].left)
           &&(rectRWP.packedRegLeft < regionInfo->GetSourceInfo()[i].left + regionInfo->GetSourceInfo()[i].width)
           &&(rectRWP.packedRegTop >= regionInfo->GetSourceInfo()[i].top)
           &&(rectRWP.packedRegTop < regionInfo->GetSourceInfo()[i].top + regionInfo->GetSourceInfo()[i].height) ){
               source_idx = i;
               return regionInfo->GetSourceInfo()[i].qualityRanking;
           }
    }
    return 0;
}

 RenderStatus CubeMapRenderTarget::TransferRegionInfo(std::map<int32_t, std::vector<TileInformation>>& org_region)
{
    if(NULL==this->m_rsFactory){
        return  RENDER_NULL_HANDLE;
    }

    RenderStatus ret = RENDER_STATUS_OK;

    std::map<uint32_t, RenderSource*> mapRenderSources = m_rsFactory->GetRenderSources();

    org_region.clear();

    //add all tiles in different source into a map and organized via quality ranking
    for(auto it=mapRenderSources.begin(); it!=mapRenderSources.end(); it++){
        uint32_t video_id = it->first;
        RegionData *regionInfo = it->second->GetCurrentRegionInfo();
        if (regionInfo == NULL || regionInfo->GetRegionWisePacking() == NULL \
        || regionInfo->GetSourceInfo() == NULL || regionInfo->GetSourceInRegion() > 2 || regionInfo->GetSourceInRegion() <= 0){
            continue;
        }
        uint16_t numRegion = regionInfo->GetRegionWisePacking()->numRegions;
        for(int32_t idx=0; idx<numRegion; idx++){
            TileInformation tile_info;
            // 1. get basic information for tile_info
            tile_info.projRegLeft     = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].projRegLeft;
            tile_info.projRegTop      = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].projRegTop;
            tile_info.projRegWidth    = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].projRegWidth;
            tile_info.projRegHeight   = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].projRegHeight;
            tile_info.packedRegLeft   = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].packedRegLeft;
            tile_info.packedRegTop    = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].packedRegTop;
            tile_info.packedRegWidth  = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].packedRegWidth;
            tile_info.packedRegHeight = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].packedRegHeight;
            tile_info.packedPicWidth  = regionInfo->GetRegionWisePacking()->packedPicWidth;
            tile_info.packedPicHeight = regionInfo->GetRegionWisePacking()->packedPicHeight;
            tile_info.video_id        = video_id;
            tile_info.transformType   = regionInfo->GetRegionWisePacking()->rectRegionPacking[idx].transformType;

            std::pair<uint32_t, uint32_t> coord(tile_info.projRegLeft / tile_info.projRegWidth, tile_info.projRegTop / tile_info.projRegHeight);
            int32_t source_idx = 0;
            int32_t quality = findQuality(regionInfo, regionInfo->GetRegionWisePacking()->rectRegionPacking[idx], source_idx);
            tile_info.tile_id = (coord.first + 1) + m_rsFactory->GetHighTileCol() * coord.second;
            // 2. get face_id according to proj left/top
            uint32_t cube_map_face_width = m_rsFactory->GetSourceResolution()[0].width / CUBE_MAP_COL;
            uint32_t cube_map_face_height = m_rsFactory->GetSourceResolution()[0].height / CUBE_MAP_ROW;
            uint32_t rowIdx = tile_info.projRegTop / cube_map_face_height;
            uint32_t colIdx = tile_info.projRegLeft / cube_map_face_width;
            uint32_t faceIDInOMAF = rowIdx * CUBE_MAP_COL + colIdx;
            tile_info.face_id = mOMAF2GLFaceIDMap[faceIDInOMAF]; // tile_info.face_id is corresponding to face_id in OpengGL.
            // 3. correct proj left/top in face
            tile_info.projRegTop -= cube_map_face_height * rowIdx;
            tile_info.projRegLeft -= cube_map_face_width * colIdx;
            // 4. push tile_info into map
            mQualityRankingInfo.mapQualitySelection[quality].push_back(tile_info);
            if (m_transformType.find(tile_info.face_id) != m_transformType.end())
            {
                if (m_transformType[tile_info.face_id] != tile_info.transformType) // exist and changed
                {
                    m_transformType.erase(tile_info.face_id);
                    m_transformType.insert(make_pair(tile_info.face_id, tile_info.transformType));
                }
            }
            else if (m_transformType.find(tile_info.face_id) == m_transformType.end()) // not existed
            {
                m_transformType.insert(make_pair(tile_info.face_id, tile_info.transformType));
            }
        }
        it->second->SafeDeleteRegionInfo();
        regionInfo = NULL;
    }
    return ret;
}

RenderStatus CubeMapRenderTarget::GetRenderMultiSource(std::map<int32_t, std::vector<TileInformation>> &regionInfoTransfer)
{
    //1.transfer the regionInfo
    return TransferRegionInfo(regionInfoTransfer);
}

std::vector<uint32_t> CubeMapRenderTarget::GetRegionTileId(struct SphereRegion *sphereRegion, struct SourceInfo *sourceInfo)
{
    std::vector<uint32_t> RegionTileId;
    if (NULL == sphereRegion || NULL == sourceInfo)
    {
        return RegionTileId;
    }
    uint32_t width = sourceInfo->sourceWidth;
    uint32_t height = sourceInfo->sourceHeight;
    uint32_t tileRowNumber = sourceInfo->tileRowNumber;
    uint32_t tileColumnNumber = sourceInfo->tileColumnNumber;
    //1. process sphereregion
    uint32_t centerX = float(((sphereRegion->centreAzimuth) >> 16) + 180) / 360 * width;
    uint32_t centerY = float(((sphereRegion->centreElevation) >> 16) + 90) / 180 * height;
    uint32_t marginX = float((sphereRegion->azimuthRange) >> 16) / 360 * width;
    uint32_t marginY = float((sphereRegion->elevationRange) >> 16) / 180 * height;
    //1.1 transfer to lefttop and rightbottom
    uint32_t leftTopX = (centerX - marginX / 2 + width) % width;
    uint32_t leftTopY = (centerY - marginY / 2 + height) % height;
    uint32_t rightBottomX = (centerX + marginX / 2 + width) % width;
    uint32_t rightBottomY = (centerY + marginY / 2 + height) % height;
    u_int32_t delta = 1;
    //fix
    rightBottomX = rightBottomX % (width / tileColumnNumber) == 0 ? (rightBottomX - delta + width) % width : rightBottomX;
    rightBottomY = rightBottomY % (height / tileRowNumber) == 0 ? (rightBottomY - delta + height) % height : rightBottomY;
    //1.2 transfer to (0,0), (0,1), (1,0) …
    uint32_t s1 = leftTopX / (width / tileColumnNumber);
    uint32_t s2 = leftTopY / (height / tileRowNumber);
    uint32_t e1 = rightBottomX / (width / tileColumnNumber);
    uint32_t e2 = rightBottomY / (height / tileRowNumber);

    // need to consider the bundary change fix the problem when region only in one tile using >=
    for (uint32_t p = s1; p <= (e1 >= s1 ? e1 : e1 + tileColumnNumber); p++)
    {
        for (uint32_t q = s2; q <= (e2 >= s2 ? e2 : e2 + tileRowNumber); q++)
        {
            RegionTileId.push_back(p % tileColumnNumber + (q % tileRowNumber) * tileColumnNumber + 1); //index from 1
        }
    }
    sort(RegionTileId.begin(), RegionTileId.end());
    return RegionTileId;
}

RenderStatus CubeMapRenderTarget::TransferTileIdToRegion(uint32_t tileId, struct SourceInfo *sourceInfo, SphereRegion *sphereRegion)
{
    if (NULL == sphereRegion || NULL == sourceInfo)
    {
        return RENDER_ERROR;
    }
    //1.transfer tileId to coord()
    uint32_t tileColumnNumber = sourceInfo->tileColumnNumber;
    uint32_t coordX = (tileId - 1) % tileColumnNumber;
    uint32_t coordY = (tileId - 1) / tileColumnNumber;
    //2.transfer to 0-width and 0-height
    sphereRegion->azimuthRange = sourceInfo->sourceWidth / sourceInfo->tileColumnNumber;
    sphereRegion->elevationRange = sourceInfo->sourceHeight / sourceInfo->tileRowNumber;
    sphereRegion->centreAzimuth = coordX * (sourceInfo->sourceWidth / sourceInfo->tileColumnNumber) + sphereRegion->azimuthRange / 2;
    sphereRegion->centreElevation = coordY * (sourceInfo->sourceHeight / sourceInfo->tileRowNumber) + sphereRegion->elevationRange / 2;
    //3.transfer to standard
    sphereRegion->azimuthRange = uint32_t(float(sphereRegion->azimuthRange) / sourceInfo->sourceWidth * 360) << 16;
    sphereRegion->elevationRange = uint32_t(float(sphereRegion->elevationRange) / sourceInfo->sourceHeight * 180) << 16;
    sphereRegion->centreAzimuth = int32_t(float(sphereRegion->centreAzimuth) / sourceInfo->sourceWidth * 360 - 180) << 16;
    sphereRegion->centreElevation = int32_t(float(sphereRegion->centreElevation) / sourceInfo->sourceHeight * 180 - 90) << 16;
    return RENDER_STATUS_OK;
}

RenderStatus CubeMapRenderTarget::GetTilesInViewport(float yaw, float pitch, float hFOV, float vFOV, uint32_t row, uint32_t col, std::vector<uint32_t>& TilesInViewport)
{
    if (hFOV <= 0 || vFOV <= 0)
    {
        return RENDER_ERROR;
    }
    struct SphereRegion region;
    region.azimuthRange = uint32_t(hFOV) << 16;
    region.elevationRange = uint32_t(vFOV) << 16;
    region.centreAzimuth = uint32_t(yaw) << 16;
    region.centreElevation = uint32_t(pitch) << 16;
    struct SourceInfo info;
    info.sourceWidth = m_rsFactory->GetSourceResolution()[0].width;
    info.sourceHeight = m_rsFactory->GetSourceResolution()[0].height;
    info.tileRowNumber = row;
    info.tileColumnNumber = col;
    TilesInViewport = GetRegionTileId(&region, &info);
    return RENDER_STATUS_OK;
}

VCD_NS_END
