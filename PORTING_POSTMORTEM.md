# Gaslamp 全景视频 → WebAssembly 移植：失败复盘

> 目标：在网页端正常播放 `~/source/IVS_webpage/gaslamp/Gaslamp` 里的全景视频。
> 本文档基于对以下资产的只读排查：本仓库（`~/source/Immersive-Video-Sample`，HEAD `f501784`）、
> `~/source/IVS_original`、`~/source/IVS2`、`~/source/IVS_webpage`、`~/source/curl_py`、
> `~/source/ffmpeg*`、`~/source/emsdk`、`llm/*.txt`（当时的 LLM 对话记录）。

---

## 0. 结论速览

> **最终结果（2026-10-06）**：路线 C 已跑通。Gaslamp 全景视频现在能在浏览器里
> **完整播放**（整条 2 分 46 秒、约 5000 帧/流），全程堆稳定在 **443MB**
> （此前是 20 秒撞 4GB 然后中止），无运行时报错。
> 关键修复见 §9.7。截图见 `porting-evidence/playback_fixed2.png`。

失败不是一个原因，而是**四层叠加**：

| 层级 | 性质 | 一句话 |
|---|---|---|
| **P0 直接原因** | 最后提交的状态本身就是「残废」的 | 下载路径被 3 句调试桩彻底短路，收字节的回调也被短路。程序**不可能**下载到任何数据 —— 这正好对应「没报错但一直不正常」 |
| **P1 架构原因** | curl → emscripten_fetch 的语义鸿沟 | 自制的 fake curl 漏掉了响应头回调，OMAF 永远读到 `content length = -1`，于是把**每一个**下载任务判为 timeout 并无限重试 |
| **P2 平台原因** | wasm 的网络后端 | 真 libcurl（**8.8.0**）确实编出来也链进去了，但它的 socket 层依赖 Emscripten 的 WebSocket 代理。**你自己在 commit `189987d` 里已经写下结论：`this fails because of web socket proxying bug`** |
| **P3 内容原因** | Gaslamp 不是「一个视频」 | 只有 OMAF 分块（MCTS tile）+ extractor 轨道，没有完整 8K 轨道；标准解码器解不了大多数块；8K HEVC 软解在 wasm 里本来也不现实 |

**最重要的一条**：P0 意味着「上一次浏览器里的运行结果」根本不能用来判断架构是否可行。你被测的是一个被短路过的程序。

---

## 1. 时间线（由 git / 文件 mtime / llm 日志还原）

```
2025-04-18  clone 上游 IVS
2025-04-26  ffmpeg.wasm clone（改了 Dockerfile，但从未跑完 docker build）
2025-04-27  /Users/hasee/source/ffmpeg 7.1.git configure 失败（x264 not found）
2025-05-07  curl_py/compile_curl.py 改编自 emsdk ports/curl.py（curl 7.68）→ 编完 96 个 .o 后脚本崩溃
2025-05-08  llm/prompt.txt —— 第一次问「fake curl 为什么下不动」
2025-05-10  llm/testprompt.txt —— 日志显示 Header content length=-1 / Task timeout
2025-05-11  llm/old.func.txt
2025-05-12  ffmpeg_wasm_lib/lib/libcurl.a（curl 8.8.0，HTTP-only）生成
2025-05-14  IVS_original/src/build/client/player/render.wasm 64MB 链接成功
2025-05-16  IVS_webpage/render.wasm 58MB（真 curl 版）
2025-05-23  4a25d6f "running but error"     ← 加入 3 处短路桩 + fake_curl 源码
2025-05-23  189987d "add build script for real curl / this fails because of web socket proxying bug"
2025-05-23  f501784 "Create index.html"
```

---

## 2. 直接原因（P0）：最后的状态不会下载任何数据

四处在调试时插入、事后没有移除的「短路桩」（全部在 `4a25d6f` 引入）：

```
src/OmafDashAccess/OmafDashDownload/OmafCurlMultiHandler.cpp:589
    OMAF_STATUS OmafCurlMultiDownloader::startTaskDownload(void) noexcept {
        return ERROR_NONE;          // <-- 无条件返回，整个函数体是死代码
      try { ... }

src/OmafDashAccess/OmafDashDownload/OmafCurlEasyHandler.cpp:238
    OMAF_STATUS OmafCurlEasyDownloader::start(...) noexcept {
        return ERROR_NONE;          // <-- 无条件返回，永远不发请求
      try { ... }

src/OmafDashAccess/OmafDashDownload/OmafCurlEasyHandler.cpp:363-365
    size_t OmafCurlEasyDownloader::curlBodyCallback(char *ptr, size_t size, size_t nmemb, void *userdata) noexcept {
      size_t bsize = size * nmemb;
      return bsize;                 // <-- 收到的字节直接扔掉，不交给上层
      try { ... }
```

（`curlBodyCallback` 在 :227 被注册为 `CURLOPT_WRITEFUNCTION`。）

再加上渲染/主循环也被砍掉：

```
src/player/player_lib/Api/MediaPlayer_Linux.cpp:159,227
    //do { ... } while (!quitFlag);   // 整个 Play() 只跑一帧
src/player/app/linux/render.cpp:442
    //emscripten_set_main_loop(main_loop_play, 20, 1);
    for (int i = 0; i < 5; i++) main_loop_play();   // 一共 5 帧
```

**后果**：`startTaskDownload()` 永不启动任务 → `OmafCurlEasyDownloader::start()` 即使被调用也不发 HTTP 请求 →
即使有数据回来 `curlBodyCallback` 也全部丢弃。程序初始化、渲染、退出，全程无异常。
这就是「没有报错，但运行一直有问题、偶尔有运行时错误」的直接来源。

> 这三句很可能是当时用来「二分定位崩溃」的临时手段，但被 commit 进去了，之后再没删掉。

---

## 3. 架构原因（P1）：fake curl 的语义不完整

`src/OmafDashAccess/fake_curl/{include/curl/curl.h, src/curl.cpp}`（484 + 1068 行）用 `emscripten_fetch`
实现了 curl 的一个子集。核心缺陷（都有代码依据）：

1. **`CURLOPT_HEADERFUNCTION` 从来没有被调用过。**
   `grep -n 'header_function' src/curl.cpp` 只命中结构体成员定义；`common_fetch_onsuccess` / `onerror`
   里只调用 `write_function`，`emscripten_fetch_attr_t::onheaders` 也从未设置。
   OMAF 依赖 header 回调解析 `Content-Length` / `Content-Range` 来构造
   `easy_h_downloader_->getIndexRange()`（分块 range 下载的索引表）。**这个表永远是空的。**

2. **`CURLINFO_CONTENT_LENGTH_DOWNLOAD_T` 语义错误。**
   `curl.cpp:265` `easy_state->info_content_length_download_t = fetch->numBytes;`
   `numBytes` 是「本次实际收到的 body 字节数」，不是响应头里的资源长度；HEAD 请求时恒为 0。
   而 OMAF 正是拿它和 `task->streamSize()` 做相等比较来决定 FINISH / TIMEOUT
   （`OmafCurlMultiHandler.cpp:673,686`）。

3. **OMAF 需要的 getinfo 大多是空的。**
   `curl_easy_getinfo` 只实现了 6 个 case（`curl.cpp:626-634`）。OMAF 在
   `OmafCurlEasyHandler.cpp:131-162` 调用 `CURLINFO_{NAMELOOKUP,CONNECT,APPCONNECT,PRETRANSFER,STARTTRANSFER,REDIRECT}_TIME_T`，
   全部落到 `default` → 返回 `CURLE_UNKNOWN_OPTION` 且**不写输出**，调用方读到的是未初始化的栈值。

4. **忙等 / 不 yield。**
   `curl_multi_perform` 把 `*running_handles_out = mstate->active_fetches.size()`；
   而 OMAF 的 worker 循环只在 `still_alive == max_parallel_` 时才调 `curl_multi_wait`
   （`OmafCurlMultiHandler.cpp:572-577`）。这两个量语义不同，几乎永远不相等，
   于是 pthread 会 100% 空转。

5. **`curl_multi_wait` 在 pthread 里用 `emscripten_sleep()`**（`curl.cpp:974+`），
   需要该线程也编译 Asyncify；而 `OmafDashAccess/CMakeLists.txt` 里 `-sASYNCIFY=1` 是被注释掉的。

6. **死锁与 UAF**：`onsuccess` 的加锁顺序是 easy→general（:244→:286），而 `multi_perform` /
   `remove_handle` / `info_read` 是 general→easy（:794→:797）—— 经典 ABBA 死锁；
   `curl_easy_cleanup` 在 `state->multi_parent` 非空时只置空指针（:870）却仍然 `delete state`（:897），
   而 `multi->easy_handles_managed` 里还留着这个悬垂指针。

7. **根本矛盾**：`emscripten_fetch` 是**事件循环驱动、回调式**的；而 OMAF 下载器是**阻塞式 pthread + 同步
   `curl_multi_*` 轮询**。从 pthread 里发起 fetch、再靠跨线程消息把回调送回该 pthread，
   是 Emscripten 里最容易出现「看起来在跑、实际不同步」的场景。

**与当时日志完全吻合**（`llm/testprompt.txt` 末尾）：

```
Add to multi handler transfer for url: .../Test.mpd
3-task id 17179869184, task count=0
Remove transfer for url: .../Test.mpd, handler: 1091608864
Header content length=-1
Task timeout, url=.../Test.mpd
To start transfer for url: .../Test.mpd     <-- 又重试，无限循环
```

> ⚠️ 一个容易踩的坑：`OmafDashAccess/CMakeLists.txt:20` 和 `:60` 里 fake_curl 的引用**都是注释掉的**，
> 所以 **fake_curl 从未被编译进任何产物**。当前构建链接的是真 libcurl。
> 如果哪天把这两行取消注释而忘了删 `:68 TARGET_LINK_LIBRARIES(OmafDashAccess curl)`，
> 会同时拿到两套 `curl_*` 定义 + 一套 7.68 时代的假头文件（`CURLINFO_LASTONE=57` vs 真 8.8.0 的 `66`）。

---

## 4. 平台原因（P2）：真 curl 编出来了，但传输层在浏览器里不通

**你自己的 commit message 就是结论**（`189987d`）：

```
add build script for real curl

this fails because of web socket proxying bug
```

事实链：

* `src/OmafDashAccess/fake_curl/build_real_curl.sh` 是 `emconfigure ./configure && emmake make`
  构建 **curl 8.8.0** 的脚本，`--without-ssl --disable-proxy --disable-http-auth ... --enable-http`；
* 产物 `~/source/ffmpeg_wasm_lib/lib/libcurl.a`（446 KB，5/12）经核实是真的 wasm 归档：
  **170 个 libtool 成员、libcurl/8.8.0、wasm32-unknown-emscripten、协议只有 dict+http、无 TLS**；
  socket 层是编进去的（`cf-socket.o` / `connect.o` / `hostip.o` / `select.o`），
  但 `socket/connect/recv/send/getaddrinfo/select` 全部是 **undefined**，要靠 Emscripten libc 在最终链接时解析。
* `~/source/IVS_original/src/build/client/player/render.wasm`（64 MB，5/14）确实用 `-lcurl` 链接成功
  （`CMakeFiles/render.dir/linkLibs.rsp`）。

但把最终 wasm 编译后看 import 表：

```
imports: 131  { env: 124, wasi_snapshot_preview1: 7 }
env.__syscall__newselect     <-- select 有
env.__syscall_pipe / fcntl64 / ioctl / openat / stat64 ...
（没有任何 socket / connect / getaddrinfo / getsockopt）
```

即 **libcurl 的 socket 层在最终产物里被丢弃/无法解析**。Emscripten 里要让 POSIX socket 工作，
必须走 `-sPROXY_POSIX_SOCKETS`，而它需要一个**额外的 WebSocket 代理服务器**在跑
（浏览器本身不允许 JS 直接开 TCP）。这正是 commit message 说的 "web socket proxying bug"。

另一条并行的 `~/source/curl_py` 路线（curl 7.68）其实**从未产出过库**：
`compile_curl.py` 是 emsdk `tools/ports/curl.py` 的手改版，逐文件 `emcc -c`，
96 个 `.o` 全部生成（其中 35 个是 249 字节的空壳），但脚本在最后
`final = os.path.join(build_dir,'curl',libname)`（:192）因 `libname` 未定义直接 `NameError` 崩溃，
而且**根本没有调用 `create_lib`/`ar`**，所以从来没有 `libcurl.a`，也没有日志留下。

---

## 5. 构建配置问题（放大了上面每一条）

来自 `src/player/app/CMakeLists.txt` 与 `link.txt`：

* `-g4` + `-sASSERTIONS=2` + `-sSAFE_HEAP=1` + `-sASYNCIFY=1` + `-sFULL_ES3=1` + `-sPTHREAD_POOL_SIZE=51`
  → 58–64 MB wasm，且 SAFE_HEAP 会让所有内存访问慢一个数量级。这是**调试配置**，不是能播 8K 视频的配置。
* 链接了 `x264 x265`（**编码器**，解码用不到）、`avformat avfilter avdevice`，还混入了
  `/opt/homebrew/include`、`/opt/homebrew/lib`（macOS 原生库）。
* `render.js` 是 pthreads 构建（`render.worker.js` 存在，`SharedArrayBuffer` 必需），
  但 `index.html:7-8` 用 `<meta http-equiv="Cross-Origin-Embedder-Policy">` 来设置 COOP/COEP。
  `http-equiv` 只支持有限的几个指令，COOP/COEP **必须由 HTTP 响应头下发**；
  如果这里没生效，`SharedArrayBuffer` 不可用，pthreads 在启动阶段就废了 —— 需要实测确认。
* **配置自相矛盾**：`render.cpp` 里内嵌的 config 指向
  `http://127.0.0.1:8000/Gaslamp/Test.mpd`（走网络），
  但构建时又用 `--preload-file .../gaslamp@/` 把 256 MB 内容打进 `render.data`（走虚拟 FS）。
  两条路互斥；虚拟 FS 里的路径是 `/Gaslamp/Test.mpd`、`/Gaslamp/Test_track1.1.mp4`…
* wasm 版 ffmpeg 是普通 **ffmpeg 5.1.4**（HEVC 解码器在，`CONFIG_HEVC_DECODER 1`），
  但**不含任何 OMAF 补丁**（`tiled_dash_dec` / `bypass_hevc_decoder` / `vf_transform360` /
  `avcodec_receive_frame2` 全部缺席），也没有任何硬件解码路径。

---

## 6. 内容原因（P3）：Gaslamp 本身不是「一个视频」

`Test.mpd` 解析结果（87 个 Representation，`mediaPresentationDuration=PT2M46.666S`，166 段/轨）：

* **`AdaptationSet id=0`**：`track0_$Number$.m4s`，8192×4096 完整 ERP —— **文件在磁盘上根本不存在**，
  全盘搜索无 `track0_*.m4s`、无 `VOD8K/` 目录。
* **`AdaptationSet 1..32`**：8×4 网格的 1024×1024 MCTS 分块（SRD 偏移 0..7168 × 0,1024,2048,3072）。
* **`AdaptationSet 33..36`**：4 个 1024×512 的子块。
* **`AdaptationSet 1000..1049`**：OMAF **extractor 轨道**（5120×3072 / 5120×4096 / 6144×3072 / 7168×3072），
  带 `SupplementalProperty schemeIdUri="urn:mpeg:dash:preselection:2016"`
  （例如 `ext1000,1000 32 31 26 25 24 23 18 17 16 15 10 9 33 34 35 36 33 34`）——
  它们是引用上面那些 tile 的「拼装轨道」，**单独喂给普通解码器是解不出来的**。
* 编码：`resv.podv+ercm.hvc1.2.4.L90.80` / `hvc2.2.4.L120.80`，即 HEVC Main / Main10，Level 6.0，
  sample entry 是 OMAF 的 **`resv`（restricted scheme）**，标准工具链不认识。

**实测结果**（本机 `ffmpeg` 8.x）：

* 把 init segment 里的 `resv` 改名成 `hvc1` 之后，`ffprobe` 能识别成 hevc；
* 但只有 **track1 和 track33**（都是左上角那块，slice address 从 0 开始）能解出帧，
  其余 34 个 tile 全部 0 帧，报 `Skipping invalid undecodable NALU: 0/1` / `PPS changed between slices`；
* 解出的帧是 8192×4096 的整幅画布，只有该 tile 所在矩形有画面、其余是绿底 —— 这正是 OMAF MCTS 分块模型：
  **要重建一帧，必须把所有 tile 解出来再按 SRD 位置贴回去**。

标准解码器不接受「slice address 不从 0 开始」的 MCTS 子码流，这正是本仓库里
`src/ffmpeg/patches/FFmpeg_OMAF.patch` 中 `bypass_hevc_decoder.c` 存在的原因。

**实测截图**（把 `resv` 改名 `hvc1` 后用 ffmpeg 解第 1 秒）：
本地文件 `porting-evidence/tile_track1_decoded.png` 和 `tile_track33_decoded.png`。

> 注：截图属于二进制产物，按约定不纳入版本库（见 `.gitignore` 里的 `porting-evidence/`），
> 这里保留文字记录。两者解出的都是整幅 8192×4096 画布，只有对应 tile 的位置有画面，
> 其余是绿色 —— 绿色区域就是「该 tile 未覆盖」的部分，一帧完整画面需要把 32 个 tile 贴回去。

---

## 7. 可选路线

### 路线 A —— 离线重建 + 轻量 WebGL 播放器（推荐）

把 Gaslamp 离线「烘焙」成一个普通全景视频，网页端只负责解码 + 球面渲染。

* 用 OMAF patch 版 FFmpeg（或其它能处理 MCTS 子码流的解码器）逐 tile 解码，
  按 MPD 的 SRD 位置贴回 8192×4096 ERP，再编码成浏览器友好的编码/分辨率（如 4K H.264，或 8K HEVC/AV1）；
* 网页端只需 `<video>` + 一个几十行的 WebGL equirectangular 渲染器 + 鼠标拖拽转视角。
* **优点**：工作量可控（天级），不碰 pthreads/curl/EGL 那堆坑，播放流畅。
* **缺点**：失去 OMAF 的视口自适应；分辨率或体积要取舍。

### 路线 B —— 在浏览器里写真正的 OMAF 客户端（JS/TS）

`fetch` + `WebCodecs.VideoDecoder` + `WebGL2`。

* 自己解析 MPD、按视口取 tile、拼成 HEVC 码流、解码、贴到纹理图集、球面渲染；
* **优点**：保留视口自适应，架构正确，性能远好于 wasm 软解。
* **缺点**：工作量最大（周级）；依赖浏览器 HEVC 支持（Safari 原生可用；Chrome 需要平台硬件解码器）；
  仍需自己实现 extractor 解析或「全 tile 拼装」。

### 路线 C —— 继续 wasm 移植

* 需要：把 OMAF-patched FFmpeg 也编到 wasm、给 curl 一个真实的 wasm 传输层
  （或彻底把下载器改成异步重写）、去掉 SAFE_HEAP/ASYNCIFY/PTHREAD_POOL_SIZE=51 这类调试开关；
* **优点**：复用现有 C++ 视口/渲染逻辑。
* **缺点**：8K HEVC 软解在 wasm 里性能不可接受；工作量与风险最大。

---

## 8. 复现/取证命令（供复核）

---

## 9. 路线 C 实施记录（2026-10-06）

在选定「先把 wasm 移植修到能跑」之后，实际推进到如下状态：**能构建、能在浏览器里启动、能从虚拟文件系统读取并下载分片、能创建解码器**。目前卡在最后一个架构级问题上。

### 9.1 已修复的问题

| # | 问题 | 位置 | 说明 |
|---|---|---|---|
| 1 | **整个项目根本编译不过** | `src/OmafDashAccess/CMakeLists.txt`、`src/player/app/CMakeLists.txt` | `4a25d6f` 加入的 `INCLUDE_DIRECTORIES(<emsdk>/cache/sysroot/include)` 把 emsdk 的 sysroot 头目录当成普通 `-I`，劫持了 `stddef.h`/`math.h`，任何 C++20 编译单元都会报 `no member named 'nullptr_t'`。**最后一次成功构建（5/16）之后，这个仓库已经无法重新编译。** 已删除。 |
| 2 | CMake 4.x 拒绝 `CMAKE_MINIMUM_REQUIRED(VERSION 2.8)` | 6 个 CMakeLists | 统一提升到 3.5。 |
| 3 | 三处调试短路桩 | `OmafCurlMultiHandler.cpp:589`、`OmafCurlEasyHandler.cpp:238`、`:365` | 见 §2。已移除。 |
| 4 | **两处被调试日志破坏的控制流** | `OmafCurlMultiHandler.cpp:153-155,166-168` | 原本是 `if (bad) return ERROR_NULL_PTR;`，插入日志后少了大括号，`return` 变成**无条件执行** → `createTransferForTask` 永远失败 → 无限打印 `Failed to create the transfer!`。已补上花括号。 |
| 5 | 本地媒体模式是死路 | `OmafDashSource.cpp` | URL 不带 scheme 时 `mIsLocalMedia=true`，但代码因此**不创建 segment client、也不启动 reader 线程**，`dash_client_` 为 null → 分片永远读不到。现在 local 模式同样创建 client 并启动线程。 |
| 6 | 没有可用的网络传输层 | 新增 `src/OmafDashAccess/local_curl/local_curl.cpp` | 用 `fopen/fread` 实现 OMAF 用到的那 16 个 curl 函数（同步语义，与真 libcurl 一致），URL 按 basename 解析到预加载的内容目录。已从链接中去掉真 libcurl。 |
| 7 | 主循环只跑 5 帧 | `src/player/app/linux/render.cpp:442` | 改成 `emscripten_set_main_loop(main_loop_play, 0, 1)`。 |
| 8 | 内存/栈配置是调试级 | `src/player/app/CMakeLists.txt` | 去掉 `-g4 / -sASSERTIONS=2 / -sSAFE_HEAP=1 / -sPTHREAD_POOL_SIZE=51 / -sPROXY_POSIX_SOCKETS`；加 `ALLOW_MEMORY_GROWTH`、`INITIAL_MEMORY=256MB`、`MAXIMUM_MEMORY=2GB`、`STACK_SIZE=4MB`、`DEFAULT_PTHREAD_STACK_SIZE=2MB`、`PTHREAD_POOL_SIZE=4`。wasm 从 58.7 MB 降到 47.6 MB。 |
| 9 | COOP/COEP 用 `<meta>` 写 | `webpage/index.html` | 改成真实的 HTTP 响应头，由新增的 `tools/serve_wasm.py` 下发。同时修掉 index.html 里**两个 id 相同的 canvas**。 |

### 9.2 当前实际运行状态（浏览器实测）

```
WASM runtime initialized
loaded config
[local_curl] content root = '/Gaslamp'
openmedia media_url: /Gaslamp/Test.mpd
Start the dash source http client!
To parse the mpd file: /Gaslamp/Test.mpd
start streaming / start reader thread
set resolution success                       <- GL 上下文与主线程 shader 都成功
Download Initial OmafSegment for AdaptationSet 7
To open the url: /Gaslamp/Test_track33.20.mp4   <- 分片从虚拟 FS 读到了
Header content length=15344                     <- local_curl 给出的长度是对的
Start to stitch packets! and pts is 70          <- 360SCVP 正在拼接 tile
decoder manager got dash packet size: ...
DecoderManager::CreateVideoDecoder
```

即：MPD 解析、视口选块、分片下载、sidx 解析、tile 拼接全部跑通，解码器开始创建。

### 9.3 剩余阻塞点：worker 线程里调 WebGL

崩溃栈（用 `render.wasm.map` 符号化后）：

```
TypeError: Cannot read properties of undefined (reading 'createShader')
  at _glCreateShader
  at VideoShader::VideoShader(std::string const&, std::string const&)
  at RenderSource::RenderSource()
  at SWRenderSource::SWRenderSource()
  at RenderSourceFactory::CreateHandler(unsigned int, unsigned int)
  at DecoderManager::CreateVideoDecoder(unsigned int, Codec_Type, unsigned long long)
  at DecoderManager::CheckVideoDecoders(...)
  at DecoderManager::SendVideoPackets(DASHPACKET*, unsigned int)
```

`DashMediaSource` 继承 `Threadable`，它的 `Run()` 是**线程体**（`DashMediaSource.cpp:495`），`ProcessVideoPacket()` → `SendVideoPackets()` 都跑在这个 pthread 上。

* `RenderSource::RenderSource()` 的**构造函数**里就构造 `VideoShader`（`RenderSource.cpp:39`）；
* `SWRenderSource::SWRenderSource()` 的构造函数里直接 `Bind()` + `SetAttrib()` + 建 mesh（`SWRenderSource.cpp:42-52`）。

在原生 Linux 上共享 GL 上下文时这能凑合（其实也是线程不安全的），但在 WebGL 里 **GL 上下文只属于主线程**，pthread 上 `GLctx` 是 `undefined`，于是抛异常并杀死 `DashMediaSource` 线程。主循环还在转，所以画面全黑、也不报致命错误。

**这不是一行能改完的问题**：`SWRenderSource` 的 `Initialize` / `CreateSourceTex` / `CreateR2TFBO` / `UpdateR2T` / `DestroyRenderSource` 全都在同一条调用链上，都跑在 worker 线程。

### 9.4 三条可选修法

* **A. 把 GL 资源创建与 `UpdateR2T` 挪到主线程**（架构上最正确）。
  让 `DecoderManager` 不在解码线程创建 `RenderSource`，改由主渲染循环惰性创建/更新。改动集中在 `RenderSourceFactory` / `DecoderManager` / `SWRenderSource`，属于中小规模重构。
* **B. 把所有 GL 调用从 pthread 代理到主线程**。
  用 `-sPROXY_TO_PTHREAD` 提供的 `emscripten_sync_run_in_main_runtime_thread()` 包一层 GL 入口。改动面可能更大也更脆弱。
* **C. 改成单线程**：让 `DashMediaSource::Run()` 的循环被主循环驱动（去掉 reader 线程）。
  会牵动 `OmafDashSource` 的读取线程与条件变量，代价最大。

### 9.5 「读取太快导致内存爆掉」——实测结论

这是很自然的一个猜测，我做了对照实验来验证。

**猜测部分成立。** 实测：读取线程在几十秒内推进到 `PTS 449`（整条流 166 秒），
而渲染循环只输出了 **1 帧**。本地文件读取是 `memcpy`，确实没有任何反压。

**但它不是 OOM 的主因。** 三组对照实验都指向同一个结论：wasm 堆以**恒定约 200 MB/s**
涨到 4 GB 上限，与下载速度、循环频率、日志量都无关：

| 实验 | 结果 |
|---|---|
| 加 1 MB/s 令牌桶限速（`local_curl`） | 堆仍然 1.3 GB@5s → 2.8 GB@10s → 4 GB@16s |
| 把 `DashMediaSource::Run()` 的 `usleep` 从 1 ms 改成 20 ms（空转降 20 倍） | 堆仍然 4 GB@20s |
| 把 `std::cout` 整个接到丢弃缓冲（日志量降到 1/3） | 堆仍然 4 GB@20s |
| 修掉两处下载线程忙等（`usleep(1000)`） | 无变化 |
| 全程只有 **2 个**解码器，`DECODE_THREAD_COUNT` 已从 16 降到 4 | 说明不是解码器数量 |

崩溃形式也从 "Cannot enlarge memory" 变成了
`Aborted(Stack overflow! Stack cookie has been overwritten ...)` —— 即**栈被踩坏**，
这是内存失控的次生现象（或一个独立的缓冲区越界 bug）。

**已经从这条线索上修好的东西**（都是有价值的独立修复）：

* `local_curl` 增加令牌桶限速，并在 config.xml 暴露旋钮：
  `<localRateLimitBytesPerSec>1048576</localRateLimitBytesPerSec>`（约 2.5× 实时码率）；
* 预加载内容从 **256 MB 降到 67 MB**：丢掉 `AdaptationSet 1000..1049`
  这 50 条 extractor 轨道（189 MB，`enableExtractor=0` 时根本用不到），
  靠 `tools/stage_content.sh` 用硬链接暂存；
* `DECODE_THREAD_COUNT` 16 → 4；
* `OmafCurlMultiDownloader::threadRunner` 与 `OmafDashSegmentHttpClientImpl::threadRunner`
  的忙等加上 `usleep(1000)`（原来的 pacing 依赖 `curl_multi_wait`，
  而它只在 `still_alive == max_parallel_` 时被调用，同步后端下永不成立）；
* `webpage/index.html` 增加 `locateFile` cache-bust —— 旧的 `render.wasm` 被缓存
  会静默掩盖每一次重建，非常容易误判。

**下一步该用的工具**：wasm 侧的分配剖析。建议
`em++ -fsanitize=address` 重建（Emscripten 支持 ASan，能在退出时报告泄漏，
并在越界发生时给出确切地址），或者接一个 `malloc` 计数钩子看是谁在持续分配。
在拿到这个数据之前，继续猜测吞吐/线程参数都是浪费。

### 9.6 内存问题的第二轮定位（ASan）

**二分定位（运行时可切换，无需重新构建）**：新增 `?stopReader=1` / `?stopStitch=1`，
经 `EM_JS` 从 URL 读进 C++（见 `render.cpp` 的 `ivs_js_flag`）。

| 实验 | 结果 |
|---|---|
| `?stopReader=1`（不启动读取线程） | **堆稳定在 256MB 长达 71 秒**，而 `Run()` 仍在以 ~950 行/秒空转 |
| `?stopStitch=1`（跳过 tile 拼接） | 仍然 4GB@20s |
| `local_curl` 限速 1MB/s | 仍然 4GB@16s |
| `std::cout` 接到丢弃缓冲 | 仍然 4GB@20s |
| 传输计数（新加） | **159 次传输 / 1.7MB 数据 → 3.8GB 堆增长 ≈ 24MB / segment** |

**结论**：泄漏（或失控增长）**完全在读取/下载/解析这条链上**，与渲染、解码、拼接循环无关。

**分配器记账**（新加 `bigalloc_probe.cpp`，`mallinfo()` + C++ 分配算子直方图）：

```
mallinfo uordblks 361MB → 664MB → 947MB → 1230MB → 1513MB   (每 60 帧 +290MB)
new live          3471 KB → 3492 KB → 3513 KB → 3535 KB      (完全平的)
```

即 **C++ 的 `operator new/delete` 完全平衡**，直方图不变；增长在**直接调用 `malloc` 的 C 代码**里。
（`-Wl,--wrap=malloc` 在 Emscripten 下没有生效，计数恒为 0，所以改用 ASan。）

**ASan（`-fsanitize=address`）查出三个真实缺陷**：

1. **heap-buffer-overflow** — `OmafMediaStream::UpdateStreamInfo()`：
   ```cpp
   memcpy_s(dst, 1024, someStdString.c_str(), 1024);   // 共 6 处
   ```
   从一个几十字节的 `std::string` 缓冲区里**读 1024 字节**，并且目标没有 NUL 结尾，
   后续所有 `printf("%s")` 都会继续越界。✅ **已修**（新增 `CopyStringToFixedBuffer()`）。

2. **container-overflow** — `VCD::MP4::BrandAtom<Atom>::FromStream()`：
   `while (str.BytesRemain() >= 4) m_compatibleBrands.push_back(...)`。
   `Stream::BytesRemain()` 是相对**整个底层缓冲区**算的，并不受该 box 长度限制，
   所以这个循环会按整个 init segment 的长度追加 brand。✅ **已加上限**（64，符合规范）；
   但 ASan 仍在**同一地址**复现同一个 container-overflow，怀疑是 emscripten 3.1.40
   自带 libc++ 的容器注解 + `__swap_out_circular_buffer` 的已知误报，**待确认**。

3. **线程池耗尽**（我这个移植引入的）— 我把 `PTHREAD_POOL_SIZE` 从 51 降到 4 之后，
   运行时报 `Tried to spawn a new thread, but the thread pool is exhausted`，流水线直接停摆
   （60 秒只完成 1 次传输，掩盖了其他所有现象，浪费了一轮排查）。
   ✅ 已改为 **32**。注意 `PTHREAD_POOL_SIZE=0`（按需创建）**也不行**：Emscripten 只能从主线程
   新建 pthread，OMAF 在非主线程里创建线程时同样会失败。改回 32 后报错为 0。

**当前最重要的矛盾（下一轮的起点）**：

| 构建 | 堆表现 |
|---|---|
| 无 ASan（dlmalloc） | 2575MB@10s → **4096MB@20s** → 栈 cookie 被覆盖中止 |
| 有 ASan（ASan 分配器） | **841MB 全程不动** |

同一份代码，只换了分配器，行为完全不同。这强烈暗示：**增长是 dlmalloc 侧的失控
（例如一次超大分配请求让 emscripten 直接把堆顶到 MAXIMUM_MEMORY，或堆元数据被踩后
chunk 再也回收不了）**，而不一定是一个逐字节的泄漏。ASan 因为换掉了分配器，把这个问题
掩盖了，同时也让流水线跑不动（60 秒只完成 1 次传输）。

**下一轮该做的**（按性价比排序）：

1. 在 `emscripten_resize_heap` / `sbrk` 上打点，看第一次"一大跳"发生在什么调用栈下
   —— 这能直接区分"真的用到 4GB"和"一次超大请求"。
2. 给 `BrandAtom` 的 container-overflow 定性：确认是 libc++ 误报还是真问题
   （可以临时禁用容器注解 `ASAN_OPTIONS=detect_container_overflow=0` 对比）。
3. 若确认是 dlmalloc 失控，考虑换分配器（`-sMALLOC=emmalloc` 或 `mimalloc`）验证。

### 9.7 内存问题的根因（已修复）

沿着 9.6 的线索，用「运行时可切换开关 + 分配器记账 + 按大小抓调用栈」三步定位，
最终找到**两个独立的根因**，都在播放路径上。修完之后视频在浏览器里稳定播放。

#### 根因 1：解码帧 FIFO 无上限（`VideoDecoder::GetFrame`）

`VideoDecoder.cpp` 里「FIFO 超限就丢帧」的代码写在 while 循环**之后**，
但循环内部的 `RENDER_WAIT` 分支直接 `return` 了：

```cpp
while (mDecCtx->get_size_of_frame() > 0) {
    if (frame->pts == pts) { ...; break; }
    else if (frame->pts > pts) {          // 正常情况："还没到这一帧"
        waitFlag = true;
        return RENDER_WAIT;               // ← 直接返回，下面的丢帧保护永远不执行
    }
    ...
}
// ... 这里永远走不到
```

日志给出了铁证：FIFO 从 0 一路涨到 **429+** 从不回落，
而 `Due to over size, drop frame pts` **一次都没出现**。
每帧 1–16MB，于是 20 秒就把 4GB 堆吃满。

**修复**：把上限判定提到 `GetFrame` 入口处，先裁 FIFO 再进入等待逻辑。
效果：堆从「4096MB @20s 后中止」变成 **稳定 919MB 持续 102 秒**。

#### 根因 2：每帧一份的 `PendingFrame` 拷贝

把帧从解码线程交给主线程时必须拷贝（解码器返回后立刻释放 AVFrame）。
我最初用「每帧 new 一个 `std::vector`」实现，结果**每渲染一帧保留约 2.2MB**：

```
liveKB 618M → 1119M → 1629M → 2136M → 2736M     (每帧 +2.2MB)
proc == drained == 1194，pend ≤ 2，framesLive == 0   ← 队列和对象都是平衡的
```

即对象确实被销毁、队列确实被抽干，但内存没有归还。
（`?noUpload=1` 能止住、`?noGL=1` 止不住，正好把范围夹在「拷贝 + 队列」这一段。）

**修复**：改成**每个 render source 复用一组上传缓冲**，用 `resize()` 原地扩容
（只在首帧和分辨率变化时才分配），而不是每帧新建 vector。

效果（约 140 秒实测）：

```
heap    369M → 369M → 443M → 443M     ← 基本不动
liveKB  147M~277M 之间波动，不再单调增长
frames  634 → 5716 → 8698
errors  0
```

#### 附带修复

* `memcpy_s(dst, 1024, someStdString.c_str(), 1024)` —— 6 处越界读（ASan：heap-buffer-overflow）。
* `BrandAtom::FromStream` 的 compatible_brands 循环按整个 segment 长度追加（ASan：container-overflow）。
* `PTHREAD_POOL_SIZE=4` 导致线程池耗尽（我引入的回归），改回 32。
* `MediaPlayer_Linux::Play()` 的 `renderCount` 等状态改成 `static`：
  `Play()` 现在每次只跑一帧，局部变量每帧归零会让 `pose->pts` 永远是 0，
  解码器产出 pts≥1 而消费端一直 `RENDER_WAIT`，**一帧都画不出来**（画面全黑）。
* `local_curl` 路径解析加缓存，去掉每次传输的 `fopen/fclose` 探测。

#### 现在可用的调试开关（URL 参数，无需重新构建）

| 参数 | 作用 |
|---|---|
| `?stopReader=1` | 不启动 OMAF 读取线程 |
| `?stopDecode=1` | 跳过解码（保留下载/解析） |
| `?stopStitch=1` | 跳过 tile 拼接 |
| `?noUpload=1` | 跳过帧拷贝 |
| `?noGL=1` | 保留拷贝、跳过 GL 上传 |
| `?probe=1` | 每 60 帧 dump 一次堆分布 |
| `?verbose=1` | 把日志渲染到页面 |

以及页面内可直接调用的接口：
`em_local_curl_transfer_count` / `em_local_curl_bytes_delivered` /
`em_probe_live_kb` / `em_probe_render_sources` / `em_probe_pending_frames` /
`em_probe_proc_calls` / `em_probe_queued_total` / `em_probe_dropped_total` /
`em_probe_drained_total` / `em_probe_uploads_total` / `em_probe_report`
（bigalloc_probe.cpp 里还接管了全局 `malloc/free`，用
`emscripten_builtin_malloc` 转发并做按大小分桶记账）。

### 9.8 已建立的复现/验证环境

```bash
# 构建（需要一个工作区内的 EM_CACHE，因为 ~/.emscripten_cache 受沙箱限制）
source ~/source/emsdk/emsdk_env.sh
export EM_CACHE=$PWD/.emcache
cd src/build/client && emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release && make player -j8

# 起服务（关键是 COOP/COEP 真实响应头）
cp webpage/index.html src/build/client/player/app/index.html
python3 tools/serve_wasm.py --root src/build/client/player/app --port 8123
# 浏览器打开 http://127.0.0.1:8123/index.html
```

---

## 10. 复现/取证命令（供复核）

```bash
# wasm 的 import 表：确认没有 socket 后端
node -e 'const fs=require("fs");const m=new WebAssembly.Module(fs.readFileSync("render.wasm"));
console.log(WebAssembly.Module.imports(m).map(i=>i.module+"."+i.name).join("\n"))'

# 确认 render.wasm 里没有 emscripten_fetch / fake curl
strings -a render.wasm | grep -c emscripten_fetch          # -> 0
strings -a render.wasm | grep -oE '^curl_[a-z_]+$' | sort -u  # -> real curl symbols

# 确认三处短路桩
grep -n -B1 -A1 'return ERROR_NONE;' src/OmafDashAccess/OmafDashDownload/OmafCurlMultiHandler.cpp
grep -n 'header_function' src/OmafDashAccess/fake_curl/src/curl.cpp   # -> 只有定义，无调用

# 确认 Gaslamp 里没有完整 8K 轨道
ls ~/source/IVS_webpage/gaslamp/Gaslamp | grep -c '^track0_'

# 确认 fake_curl 没有被编译进去
grep -n 'fake_curl' src/OmafDashAccess/CMakeLists.txt      # -> 20,60 都是注释
```
