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

#include "gtest/gtest.h"
#include <string>
#include <thread>
#include <memory>
#include <pwd.h>

#include "../OmafDashDownload/OmafDownloader.h"

using namespace VCD::OMAF;

namespace {

class DownloaderTest : public testing::Test {
 public:
  virtual void SetUp() {

    outsite_url = "https://www.baidu.com";
    valid_url = "http://127.0.0.1:8000/gaslamp/Gaslamp/Test.mpd";

    invalid_url = invalid_url + "invalid";

    valid_cmaf_url = "http://10.67.115.92:8080/testCMAFstatic/Test_track1.1.mp4";
    valid_cmaf_url_cloc = "http://10.67.115.92:8080/testCMAFstatic_cloc/Test_track17.1.mp4";
    invalid_cmaf_url = valid_cmaf_url + "invalid";

    no_proxy = "127.0.0.1,*.intel.com,10.67.115.92";
    proxy_url = "http://child-prc.intel.com:913";
    invalid_proxy_url = "http://chil-prc.intel.com:913";

    dash_client_ = OmafDashSegmentHttpClient::create(10);

    client_params.bssl_verify_host_ = false;
    client_params.bssl_verify_peer_ = false;
    client_params.conn_timeout_ = 5000;    // 5s
    client_params.total_timeout_ = 30000;  // 30s

    client_params.retry_times_ = 3;

    dash_client_->setParams(client_params);
  }

  virtual void TearDown() {

    OMAF_STATUS ret = dash_client_->stop();
    EXPECT_TRUE(ret == ERROR_NONE);
  }

  OmafDashSegmentHttpClient::Ptr dash_client_ = nullptr;

  std::string valid_url;
  std::string invalid_url;
  std::string valid_cmaf_url;
  std::string valid_cmaf_url_cloc;
  std::string invalid_cmaf_url;
  std::string outsite_url;
  std::string proxy_url;
  std::string invalid_proxy_url;
  std::string no_proxy;
  OmafDashHttpParams client_params;
};

TEST_F(DownloaderTest, Create) {
  OmafDashSegmentHttpClient::Ptr dash_client = OmafDashSegmentHttpClient::create(10);
  EXPECT_TRUE(dash_client != nullptr);
}

TEST_F(DownloaderTest, downloadSuccess) {
  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);

  DashSegmentSourceParams ds;
  ds.dash_url_ = valid_url;
  ds.timeline_point_ = 1;
  ds.enable_byte_range_ = false;

  bool isState = false;
  dash_client_->open(
      ds,
      [](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
      },
      nullptr,
      [&isState](OmafDashSegmentClient::State state) {
        EXPECT_TRUE(state == OmafDashSegmentClient::State::SUCCESS);
        isState = true;
      });
  while (!isState) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, downloadCMAFSuccess) {
  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);

  DashSegmentSourceParams ds;
  ds.dash_url_ = valid_cmaf_url;
  ds.timeline_point_ = 1;
  ds.header_size_ = 1264;
  ds.enable_byte_range_ = true;
  ds.chunk_num_ = 5;
  ds.chunk_info_type_ = ChunkInfoType::CHUNKINFO_SIDX_ONLY;
  ds.cloc_size_ = 0;
  map<uint32_t, uint32_t> indexRange;
  indexRange.insert(std::make_pair(0, 5899));
  indexRange.insert(std::make_pair(1, 14012));
  indexRange.insert(std::make_pair(2, 19248));
  indexRange.insert(std::make_pair(3, 18124));
  indexRange.insert(std::make_pair(4, 18183));

  OmafDashSegmentClient::State isState = OmafDashSegmentClient::State::STOPPED;
  size_t accum_size = 0;
  dash_client_->open(
      ds,
      [&accum_size](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
        accum_size += sb->size();
      },
      [indexRange](std::unique_ptr<VCD::OMAF::StreamBlock> sb, map<uint32_t, uint32_t>& index_range) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
        index_range = indexRange;
      },
      [&isState](OmafDashSegmentClient::State state) {
        isState = state;
      }
      );
  while (isState != OmafDashSegmentClient::State::SUCCESS) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, downloadCMAFSuccess_withCloc) {
  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);

  DashSegmentSourceParams ds;
  ds.dash_url_ = valid_cmaf_url_cloc;
  ds.timeline_point_ = 1;
  ds.header_size_ = 24;
  ds.enable_byte_range_ = true;
  ds.chunk_num_ = 10;
  ds.chunk_info_type_ = ChunkInfoType::CHUNKINFO_CLOC_ONLY;
  ds.cloc_size_ = 114;
  map<uint32_t, uint32_t> indexRange;
  indexRange.insert(std::make_pair(0, 4546));
  indexRange.insert(std::make_pair(1, 5632));
  indexRange.insert(std::make_pair(2, 6061));
  indexRange.insert(std::make_pair(3, 6612));
  indexRange.insert(std::make_pair(4, 7600));
  indexRange.insert(std::make_pair(5, 7667));
  indexRange.insert(std::make_pair(6, 7618));
  indexRange.insert(std::make_pair(7, 7620));
  indexRange.insert(std::make_pair(8, 7615));
  indexRange.insert(std::make_pair(9, 7936));

  OmafDashSegmentClient::State isState = OmafDashSegmentClient::State::STOPPED;
  size_t accum_size = 0;
  dash_client_->open(
      ds,
      [&accum_size](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
        accum_size += sb->size();
      },
      [indexRange](std::unique_ptr<VCD::OMAF::StreamBlock> sb, map<uint32_t, uint32_t>& index_range) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
        index_range = indexRange;
      },
      [&isState](OmafDashSegmentClient::State state) {
        isState = state;
      }
      );
  while (isState != OmafDashSegmentClient::State::SUCCESS) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, downloadFailure) {
  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);
  DashSegmentSourceParams ds;
  ds.dash_url_ = invalid_url;
  ds.timeline_point_ = 1;
  ds.enable_byte_range_ = false;
  bool isState = false;
  dash_client_->open(
      ds,
      [](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {

      },
      nullptr,
      [&isState](OmafDashSegmentClient::State state) {
        EXPECT_TRUE(state == OmafDashSegmentClient::State::TIMEOUT);
        isState = true;
      });
  while (!isState) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, downloadCMAFFailure) {
  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);
  DashSegmentSourceParams ds;
  ds.dash_url_ = invalid_cmaf_url;
  ds.timeline_point_ = 1;
  ds.enable_byte_range_ = true;
  ds.chunk_info_type_ = ChunkInfoType::CHUNKINFO_SIDX_ONLY;
  ds.header_size_ = 1;
  map<uint32_t, uint32_t> indexRange;
  indexRange.insert(std::make_pair(0,1));

  bool isState = false;
  dash_client_->open(
      ds,
      [](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {

      },
      [indexRange](std::unique_ptr<VCD::OMAF::StreamBlock> sb, map<uint32_t, uint32_t> &index_range) {
        index_range = indexRange;
      },
      [&isState](OmafDashSegmentClient::State state) {
        EXPECT_TRUE(state == OmafDashSegmentClient::State::TIMEOUT);
        isState = true;
      });
  while (!isState) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, proxy_success) {
  DashSegmentSourceParams ds;
  ds.dash_url_ = outsite_url;
  ds.timeline_point_ = 1;

  OmafDashHttpProxy proxy;
  proxy.http_proxy_ = proxy_url;
  // proxy.https_proxy_ = proxy_url;

  dash_client_->setProxy(proxy);

  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);

  bool isState = false;
  dash_client_->open(
      ds,
      [](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
      },
      nullptr,
      [&isState](OmafDashSegmentClient::State state) {
        EXPECT_TRUE(state == OmafDashSegmentClient::State::SUCCESS);
        isState = true;
      });
  while (!isState) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, invalid_proxy) {
  DashSegmentSourceParams ds;
  ds.dash_url_ = outsite_url;
  ds.timeline_point_ = 1;

  OmafDashHttpProxy proxy;

  proxy.https_proxy_ = invalid_proxy_url;

  dash_client_->setProxy(proxy);

  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);

  bool isState = false;
  dash_client_->open(
      ds,
      [](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {

      },
      nullptr,
      [&isState](OmafDashSegmentClient::State state) {
        EXPECT_TRUE(state == OmafDashSegmentClient::State::TIMEOUT);
        isState = true;
      });
  while (!isState) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

TEST_F(DownloaderTest, no_proxy_success) {
  DashSegmentSourceParams ds;
  ds.dash_url_ = valid_url;
  ds.timeline_point_ = 1;

  OmafDashHttpProxy proxy;
  proxy.http_proxy_ = proxy_url;
  proxy.no_proxy_ = no_proxy;
  dash_client_->setProxy(proxy);
  OMAF_STATUS ret = dash_client_->start();
  EXPECT_TRUE(ret == ERROR_NONE);
  bool isState = false;
  dash_client_->open(
      ds,
      [](std::unique_ptr<VCD::OMAF::StreamBlock> sb) {
        EXPECT_TRUE(sb != nullptr);
        EXPECT_TRUE(sb->size() > 0);
      },
      nullptr,
      [&isState](OmafDashSegmentClient::State state) {
        EXPECT_TRUE(state == OmafDashSegmentClient::State::SUCCESS);
        isState = true;
      });
  while (!isState) {
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

}  // namespace
