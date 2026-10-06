# Immersive Video Sample —— WebAssembly 移植：环境配置 / 编译 / 部署 / 使用

本文档描述如何把 `src/player/app/linux` 这个 OMAF 全景播放器编译成 WebAssembly，
在浏览器里播放 `Gaslamp` 这段 MPEG-DASH tiled 360 视频。

> 这段移植的历史背景、失败原因复盘、以及内存问题的根因分析，
> 见 [PORTING_POSTMORTEM.md](PORTING_POSTMORTEM.md)。本文只讲**怎么跑起来**。
>
> 第 1 章记录了**每个依赖的实际版本、来源，以及当初是怎么装/怎么编出来的**
> （emsdk 3.1.40 的安装方式、FFmpeg wasm 库的 OrbStack 交叉编译流程等），
> 换机器时照着第 1.7 节的清单核对即可。

---

## 0. 一句话总结

浏览器里跑的是一个 **pthreads + WebGL2 的 wasm 构建**：

* 视频内容通过 `--preload-file` 打进 Emscripten 虚拟文件系统（VFS），
  原始的 libcurl 被 [src/OmafDashAccess/local_curl/local_curl.cpp](src/OmafDashAccess/local_curl/local_curl.cpp)
  替换成**同步读 VFS**（想让内容改由 HTTP 服务器提供、不再预加载进内存，见第 7 章）；
* HEVC 解码是 **FFmpeg 5.1.4 编译出的 wasm 软解**（无硬件加速）；
* 渲染用 **WebGL2**，而且**所有 GL 调用都在主线程**（帧数据从解码线程拷到主线程再上传）；
* 因为用了 pthreads，页面**必须处于跨源隔离（cross-origin isolated）状态**才能拿到 `SharedArrayBuffer`。

---

## 1. 环境准备

### 1.1 依赖总览（含实际来源与版本）

下面这些是**本机上真实存在、并经过核对**的版本。最后一列写明了它当初是怎么来的。

| 组件 | 实际版本 | 位置 | 来源 / 备注 |
|---|---|---|---|
| Emscripten SDK | **3.1.40** | `~/source/emsdk` | 官方 `emsdk` 脚本安装；仓库从 `ghfast.top` 镜像克隆 |
| emsdk 自带 Node | **20.18.0_64bit** | `~/source/emsdk/node/` | emsdk 自己下载的，**不是**系统 node |
| emsdk 自带 Python | **3.9.2_64bit** | `~/source/emsdk/python/` | 同上 |
| Emscripten 源码树 | 3.1.40-git (`5c27e79dd`) | `~/source/emscripten` | 单独 clone 的源码（与 emsdk 装出的 upstream 同一提交，用于对照/改源码） |
| FFmpeg wasm 静态库 | FFmpeg **n5.1.4** | `~/source/ffmpeg_wasm_lib/{include,lib}` | 用下面 1.4 的 Docker 流程交叉编译 |
| ffmpeg.wasm 构建仓库 | fork，`main` @ `e2dd60e` | `~/source/ffmpeg.wasm` | fork 自 `ffmpegwasm/ffmpeg.wasm`，remote 是 `git@github.com:chaihahaha/ffmpeg.wasm`，**已推送** |
| 容器 / 交叉编译环境 | Docker **27.5.1** + BuildKit **v0.18.2** | **OrbStack** | `docker context` 当前就是 `orbstack *`（见 1.5） |
| CMake | **4.4.3** | `/opt/homebrew/bin/cmake` | 系统 cmake ≥ 3.5 即可；CMake 4 需要额外一个 policy 参数 |
| 系统 Python | 3.12.7 | | 只用来跑本地静态服务器 |
| 系统 Node | v25.9.0 | | 与构建无关（emcc 用的是 emsdk 内置 node） |
| 浏览器 | Chrome / Chromium 桌面版 | | 需要 WebGL2 + SharedArrayBuffer |

> **不需要**的东西：任何 C/C++ 原生编译环境、FFmpeg 的系统包、SDL、curl —— 全部由 emsdk 和预编译库提供。

### 1.2 emsdk / Emscripten 是怎么装的

安装过程（与官方文档一致）大致是：

```bash
# 1) 克隆 emsdk（当时走了 ghfast.top 这个 GitHub 镜像来避开网络问题）
git clone https://ghfast.top/github.com/emscripten-core/emsdk.git ~/source/emsdk
cd ~/source/emsdk

# 2) 安装并激活指定版本
./emsdk install 3.1.40
./emsdk activate 3.1.40

# 3) 每次开新 shell 都要 source 一次
source ~/source/emsdk/emsdk_env.sh
```

判断装对了没有：

```bash
emcc --version
# emcc (Emscripten gcc/clang-like replacement + linker emulating GNU ld) 3.1.40 (5c27e79dd0a9c4e27ef2326841698cdd4f6b5784)

cat ~/source/emsdk/upstream/emscripten/emscripten-version.txt
# "3.1.40"
```

**为什么是 3.1.40**：FFmpeg 的 wasm 库是在 `emscripten/emsdk:3.1.40` 这个 Docker 镜像里编出来的。
播放器的 `render.wasm` 必须用**同一个版本**的 emcc 才能安全地和那些 `.a` 链接。
换版本很可能出 ABI 问题。

#### ⚠️ `EM_CACHE` 的顺序坑

Emscripten 的缓存目录默认是 `~/.emscripten_cache`。**`emsdk_env.sh` 自己会设置 `EM_CACHE`**
（见 `emsdk/emsdk.py` 里针对旧版本 SDK 的处理），所以你如果**先 export 再 source，会被它覆盖掉**：

```bash
# ✗ 错误顺序：EM_CACHE 被 emsdk_env.sh 覆盖
export EM_CACHE=$PWD/.emcache
source ~/source/emsdk/emsdk_env.sh

# ✓ 正确顺序：先 source，再 export
source ~/source/emsdk/emsdk_env.sh
export EM_CACHE=$PWD/.emcache
emcc --version
```

如果那个目录不可写（受限环境、只读家目录、沙箱等），不设 `EM_CACHE` 会直接失败：

```
PermissionError: [Errno 1] Operation not permitted: '/Users/hasee/.emscripten_cache'
```

把缓存指到工作区里就能解决，这也是为什么建议固定写成
`export EM_CACHE=$PWD/.emcache`（`.emcache/` 已经在 `.gitignore` 里，有 160 MB 左右）。

### 1.3 关于 FFmpeg 静态库

`src/player/app/CMakeLists.txt` 里对 ffmpeg 的头文件和库路径是**绝对路径硬编码**的：

```cmake
target_include_directories(render PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/include ...)
SET(LINK_LIB ${LINK_LIB} MediaPlayer ... /Users/hasee/source/ffmpeg_wasm_lib/lib/libavcodec.a ...)
```

换机器时需要把这些路径改成你自己的。这个库的实际性质（读 `ffmpeg_wasm_lib/include/config.h`
和 `config_components.h` 核对过）：

| 项目 | 值 |
|---|---|
| 版本 | FFmpeg **n5.1.4** |
| 目标 | `--target-os=none --arch=x86_32 --enable-cross-compile --disable-asm` |
| 工具链 | `--nm=emnm --ar=emar --ranlib=emranlib --cc=emcc --cxx=em++` |
| 线程 | **`HAVE_PTHREADS 1`** —— 多线程版本，和播放器的 `-pthread` 匹配 |
| 关键解码器 | `CONFIG_HEVC_DECODER 1`、`CONFIG_H264_DECODER 1`（共启用 456 个解码器） |
| 启用的外部库 | libx264、libx265、libvpx、libmp3lame、libass、libwebp、`--enable-gpl` |
| 硬件加速 | **无** VAAPI / VideoToolbox / MediaCodec —— 纯软件解码 |

`~/source/ffmpeg_wasm_lib/` 目录结构：

```
include/            头文件（含 config.h / config_components.h / curl/）
include.zip         头文件打包
lib/                静态库
  libavcodec.a      19.7 MB
  libavutil.a  libswscale.a  libswresample.a  libavformat.a  libavfilter.a ...
  libx264.a  libx265.a
  libcurl.a         446 KB，见 1.6
lib.tar.gz          库的打包（10.5 MB）
third.tar.gz        第三方依赖打包（11 MB）
```

库里装的是 **wasm 目标文件**（不是主机原生对象），可以用
`strings libavcodec.a | grep target_features` 确认。

### 1.4 FFmpeg wasm 库是怎么编出来的（Docker 交叉编译）

构建工程在 `~/source/ffmpeg.wasm`。**这就是你问的那个仓库 —— 它是有 `.git` 的**，
而且已经推送到你的 fork：

```bash
cd ~/source/ffmpeg.wasm
git remote -v
# origin  git@github.com:chaihahaha/ffmpeg.wasm (fetch)
# origin  git@github.com:chaihahaha/ffmpeg.wasm (push)

git log --oneline -1
# e2dd60e new dockerfile          ← 你自己的提交 (chai836275709@gmail.com, 2025-05-23)

git status -sb
# ## main...origin/main           ← 与远程同步，没有未推送内容
```

> 如果你之前"没看到 `.git`"，很可能看的是 `~/source/ffmpeg_wasm_lib/` ——
> 那只是把构建产物解包出来的目录，本来就不是 git 仓库。

你改过的 `Dockerfile`（提交 `e2dd60e`）要点：

* 基础镜像 **`FROM emscripten/emsdk:3.1.40`** —— 和播放器用的 emcc 版本一致；
* **`FFMPEG_VERSION=n5.1.4`**；
* 只保留 **x264 / x265** 两个前置库，其余（libvpx、lame、ogg、theora、opus、vorbis、
  zlib、libwebp、freetype、fribidi、harfbuzz、libass、zimg）**全部注释掉** —— 因为
  播放器只需要 HEVC 解码，不需要那一整条滤镜/字幕/编码依赖链；
* 把 `ffmpeg-wasm-builder` 和 `exportor` 两个阶段也注释掉了 —— 也就是说这次构建
  **只产出原生静态库**，不产出 `ffmpeg-core.js`（不是 ffmpeg.wasm 那套 JS API）；
* 所有 `ADD` 的 URL 都走 `https://ghfast.top/github.com/...` 镜像。

`build/ffmpeg.sh` 里的 configure 骨架：

```bash
--target-os=none --arch=x86_32 --enable-cross-compile --disable-asm
--disable-stripping --disable-programs --disable-doc --disable-debug
--disable-runtime-cpudetect --disable-autodetect
--nm=emnm --ar=emar --ranlib=emranlib --cc=emcc --cxx=em++ --objcc=emcc --dep-cc=emcc
--extra-cflags="$CFLAGS" --extra-cxxflags="$CXXFLAGS"
# FFMPEG_ST 未定义时不加 --disable-pthreads，即多线程构建
```
你对这个文件只改了一处：`emmake make -j` → `emmake make -j 2`（限制并行度，省内存）。

`Makefile` 里所有构建目标最终都是：

```bash
docker buildx build --build-arg ... -o ./packages/core$(PKG_SUFFIX) .
```

> 注意：`ffmpeg_wasm_lib/include/config.h` 里记录的实际 configure 行是
> `... --enable-gpl --enable-libx264 --enable-libx265 --enable-libvpx --enable-libmp3lame --enable-libass --enable-libwebp`，
> 比当前 Dockerfile 的裁剪版更全。说明产出 `lib.tar.gz` 的那次构建用的是**较早一版 Dockerfile**，
> 之后你才把它精简到只留 x264/x265。两者都能用，当前文档以实际产出的库为准。

### 1.5 OrbStack 有没有用到？—— **用到了**

ffmpeg 的 wasm 交叉编译就是跑在 OrbStack 里的，证据：

```bash
docker context ls
# NAME            DOCKER ENDPOINT
# default         unix:///var/run/docker.sock
# desktop-linux   unix:///Users/hasee/.docker/run/docker.sock
# orbstack *      unix:///Users/hasee/.orbstack/run/docker.sock     ← 当前激活

docker info --format '{{.ServerVersion}} | {{.OperatingSystem}} | {{.Name}}'
# 27.5.1 | OrbStack | orbstack

docker buildx ls
# orbstack*  running  v0.18.2  linux/amd64 (+2), linux/arm64, ...
```

* `docker buildx build` 会走 `orbstack` 这个 builder，默认构建 `linux/amd64` ——
  也就是在 Apple Silicon 上**交叉编译出 amd64 容器**，再在容器里用 emcc 编 to wasm。
* 主机上还装了一个 OrbStack Linux 机器：`orb list` → `gt  running  gentoo  arm64  4.5 GB`。
* `desktop-linux` 这个 context 存在但 daemon 没跑 —— Docker Desktop 只是留了个占位。

**重要区分**：

| 阶段 | 需要 OrbStack / Docker 吗 |
|---|---|
| 编译 FFmpeg wasm 静态库（一次性，产物已在 `ffmpeg_wasm_lib/`） | **需要** |
| 编译并运行播放器（本文档的主流程） | **不需要**，主机上 `emcc` + `cmake` + `python3` 就够 |

也就是说，只要 `~/source/ffmpeg_wasm_lib/` 里的 `.a` 还在，换一台没有 Docker 的机器
照样能把播放器编出来。

### 1.6 那次 libcurl 的尝试（`~/source/curl_py/`）

`ffmpeg_wasm_lib/lib/libcurl.a`（446 KB，curl **8.8.0**）不是 ffmpeg 构建的产物，
是你另外单独编的：

```
~/source/curl_py/
  compile_curl.py    34 KB，用 Python 脚本驱动 curl 的 wasm 编译
  curl/              curl 8.8.0 源码
  libcurl/           产物
  using_ssl.txt      connect easy getinfo http_digest http http_proxy
```

`using_ssl.txt` 是从 OMAF 代码里抽出、实际用到的 curl 符号清单 —— 也就是想编一个
**最小化 curl**。这个库是 **HTTP-only、没有 TLS**。

这条路最后被放弃了，原因是 wasm 里**没有 socket 层**：libcurl 需要一个
`-sPROXY_POSIX_SOCKETS` + 一个 WebSocket→POSIX 的代理进程才能真正联网。
所以最终改成了 `src/OmafDashAccess/local_curl/local_curl.cpp`：同样的 curl API 子集，
改成**同步读 Emscripten 虚拟文件系统**。

现在播放器的构建**已经完全不链接 curl**（`libcurl.a` 留在目录里但没被使用）。

### 1.7 换机器时的检查清单

按顺序确认：

1. `emsdk` 装好且是 **3.1.40**：`emcc --version`
2. `ffmpeg_wasm_lib/{include,lib}` 存在，且 `libavcodec.a` 是 wasm 目标文件
3. `CMakeLists.txt` 里指向 `ffmpeg_wasm_lib` 的**绝对路径**已改成你的路径
   （`src/player/app/CMakeLists.txt` 的 `target_include_directories` 和 `SET(LINK_LIB ...)`）
4. 原始视频素材在 `~/source/IVS_webpage/gaslamp/Gaslamp`（256 MB / 14449 个文件）
5. `cmake` ≥ 3.5、`python3` 可用
6. 一个支持 WebGL2 + SharedArrayBuffer 的桌面浏览器

---

## 2. 内容准备

播放器需要的内容**不在这个仓库里**（视频文件太大）。
原始素材在 `~/source/IVS_webpage/gaslamp`，用脚本把它"搬"到仓库的 `webcontent/`：

```bash
tools/stage_content.sh
# 默认: ~/source/IVS_webpage/gaslamp  ->  ./webcontent
# 也可以显式指定:  tools/stage_content.sh <源目录> <目标目录>
```

脚本做两件事：

1. 复制 `Gaslamp/Test.mpd`；
2. **硬链接**（同文件系统时）tile 轨道 `1..36` 的 init segment 和所有分片。

为什么只搬 1..36：完整素材包 256 MB，其中 **189 MB 是 AdaptationSet 1000..1049 的 OMAF extractor 轨道**。
配置里是 `<enableExtractor>0</enableExtractor>`，播放器走 LATER_BINDING 模式，**根本不会碰这些轨道**。
`--preload-file` 会把 `webcontent/` 整个烘焙进 `render.data` 并加载进 wasm 内存，
少 189 MB 对解码 8192×4096 HEVC 是决定性的。

脚本执行完应该看到约 **67 MB**：

```bash
du -sh webcontent        # => 67M 左右
ls webcontent/Gaslamp | wc -l
```

---

## 3. 编译

### 3.1 配置（只需一次）

```bash
cd ~/source/Immersive-Video-Sample
source ~/source/emsdk/emsdk_env.sh
export EM_CACHE=$PWD/.emcache

mkdir -p src/build/client
cd src/build/client
emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
```

* `-DCMAKE_POLICY_VERSION_MINIMUM=3.5`：让老写法 `CMAKE_MINIMUM_REQUIRED(2.8)` 能在 CMake 4.x 下通过。
* 如果你改过 `CMakeLists.txt`，cmake 会自动重新配置；想强制重来就删掉 `src/build/client`。

### 3.2 编译

```bash
cd ~/source/Immersive-Video-Sample/src/build/client
make player -j8
```

产物在 `src/build/client/player/app/`：

| 文件 | 大小（参考） | 说明 |
|---|---|---|
| `render.wasm` | ~50 MB | 主模块（当前带 `-g4`，去掉会小很多） |
| `render.js` | ~1 MB | Emscripten 加载器 |
| `render.worker.js` | 小 | pthread worker |
| `render.data` | ~67 MB | 打包进去的视频内容 |

> **注意**：`index.html` 是改动源码 `webpage/index.html` 后手动复制的：
>
> ```bash
> cp webpage/index.html src/build/client/player/app/index.html
> ```
>
> `make` **不会**自动同步它。

### 3.3 关键构建参数说明

都在 [src/player/app/CMakeLists.txt](src/player/app/CMakeLists.txt) 里：

| 参数 | 作用 |
|---|---|
| `-pthread` | 启用线程，OMAF 读写/解码线程依赖它 |
| `-s ASYNCIFY=1` | OMAF 读取线程里仍有阻塞等待，需要它 |
| `-s FULL_ES3=1` `MIN_WEBGL_VERSION=2` `USE_GLFW=3` `USE_WEBGL2=1` | WebGL2 + GLFW 模拟 |
| `-s ALLOW_MEMORY_GROWTH=1` | 允许堆增长 |
| `-s INITIAL_MEMORY=268435456` | 初始 256 MB |
| `-s MAXIMUM_MEMORY=4GB` | 上限；软解大图需要 |
| `-s STACK_SIZE=4194304` `DEFAULT_PTHREAD_STACK_SIZE=2097152` | 主线程 4 MB / 线程 2 MB |
| `-s PTHREAD_POOL_SIZE=32` | 预创建线程池。**不要设成 0**：Emscripten 只能从主线程新建 pthread，OMAF 会在非主线程创建线程，会失败；也不要设得太小（4 会直接耗尽并停摆） |
| `--preload-file .../webcontent@/` | 把内容打进 `/webcontent` |
| `-s FORCE_FILESYSTEM=1` | 保证 FS 可用 |
| `-s NO_EXIT_RUNTIME=1` | 主循环不退出 |

**已刻意移除**的参数（都是调试用，代价很大）：
`-sASSERTIONS=2`、`-sSAFE_HEAP=1`、`-sPROXY_POSIX_SOCKETS`、`-lwebsocket*`、`-sFETCH=1`、`-lidbfs.js`。
网络相关全部去掉是因为现在已经不联网了 —— 内容走 VFS。

`-g4` 目前**还留着**（为了能符号化 worker 崩溃），正式发布可以去掉。

---

## 4. 部署与运行

### 4.1 必须用带 COOP/COEP 响应头的服务器

这是整个移植里最容易踩的坑：

* `render.js` 是 pthreads 构建，需要 `SharedArrayBuffer`；
* 浏览器只在**跨源隔离**的文档里暴露 `SharedArrayBuffer`；
* 跨源隔离要求响应头里带 `Cross-Origin-Opener-Policy: same-origin` 和
  `Cross-Origin-Embedder-Policy: require-corp`；
* 这两个头**必须是真实的 HTTP 响应头**。用 `<meta http-equiv=...>` 写是**无效的**
  （原始 `index.html` 就是这么写的，这也是它以前根本不可能跑起来的原因之一）。

仓库自带一个满足要求的静态服务器：

```bash
cd ~/source/Immersive-Video-Sample
nohup python3 tools/serve_wasm.py \
    --root src/build/client/player/app --port 8123 \
    > /tmp/ivs_server.log 2>&1 &
```

它会额外做两件事：`Cache-Control: no-store`（迭代时避免拿到旧的 `render.wasm`），
以及为 `.wasm` / `.data` / `.mpd` / `.mp4` 等返回正确的 MIME 类型。

### 4.2 打开页面

```
http://127.0.0.1:8123/index.html
```

**不要**用 `file://` 直接打开，也不要用不带这两个头的普通静态服务器 —— 会看到
"SharedArrayBuffer is unavailable" 并且线程起不来。

页面加载后会：解析 MPD → 选 tile → 从 VFS 读分片 → 拼接 → 软解 HEVC → WebGL2 渲染。

---

## 5. 使用方法

### 5.1 操作

**页面加载后需要先点一下画面**（获取 pointer lock），然后：

| 操作 | 效果 |
|---|---|
| **按住鼠标左键拖动** | 转动视角（ERP 全景环视） |
| **↑ / ↓ / ← / →** | 用键盘转动视角 |
| **S** | 播放 |
| **P** | 暂停 |
| **Esc** | 释放 pointer lock / 退出 |

视角灵敏度是一个常量：`m_mouseSpeed`，在
[src/player/player_lib/Render/RenderContext.h](src/player/player_lib/Render/RenderContext.h)
里，默认 `0.005f`（弧度/像素）。想调快调慢改这一个数就行。

### 5.2 调试开关（URL 参数）

这些开关在运行时读取，**不需要重新编译**，用于隔离问题：

| 参数 | 作用 |
|---|---|
| `?verbose=1` | 把播放器日志渲染到页面上（默认只计数不出 DOM，因为日志量极大） |
| `?stopReader=1` | 不启动 OMAF 读取线程 |
| `?stopDecode=1` | 跳过解码（保留下载/解析） |
| `?stopStitch=1` | 跳过 tile 拼接 |
| `?noUpload=1` | 跳过帧从解码线程到主线程的拷贝 |
| `?noGL=1` | 保留拷贝、跳过 GL 上传 |
| `?probe=1` | 每 60 帧 dump 一次堆分配分布 |

可以组合，例如 `index.html?stopDecode=1&verbose=1`。

### 5.3 在控制台里读运行时指标

页面暴露了 `window.__stats`，以及一批可以从 JS 调用的 C 函数：

```js
// 堆占用（MB）
window.__stats.heapMB()

// 下载统计
Module.ccall("em_local_curl_transfer_count", "number", [], [])   // 已完成的传输次数
Module.ccall("em_local_curl_bytes_delivered", "number", [], [])  // 已交付字节数

// 内存诊断（bigalloc_probe.cpp 接管了全局 malloc/free 做记账）
Module.ccall("em_probe_live_kb", "number", [], [])               // 当前存活字节(KB)
Module.ccall("em_probe_report", null, ["string"], ["manual"])     // 打印按大小分桶的堆分布

// 帧交接统计
Module.ccall("em_probe_proc_calls", "number", [], [])            // process() 调用次数
Module.ccall("em_probe_uploads_total", "number", [], [])         // 上传次数
```

`window.__stats.topN(8)` 会返回出现最多的日志行（`?verbose` 关闭时也在计数），
排障时很好用。

---

## 6. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 页面提示 `SharedArrayBuffer is unavailable` | 没有跨源隔离。必须用 `tools/serve_wasm.py`（或自己加 COOP/COEP 响应头） |
| 画面全黑、但日志显示在解码 | 检查 `render count` 是否在递增；如果卡在 0，说明 `Play()` 的帧计数器没有跨调用保持（见 `MediaPlayer_Linux.cpp` 里的 `static`） |
| `Tried to spawn a new thread, but the thread pool is exhausted` | `PTHREAD_POOL_SIZE` 太小或为 0，改成 32 |
| `Aborted(Cannot enlarge memory arrays ...)` | `MAXIMUM_MEMORY` 不够，或又有新的内存泄漏 |
| 堆持续增长到 4 GB | 用 §5.2 的开关二分。历史上两处根因都在帧交接路径上，见 PORTING_POSTMORTEM.md §9.7 |
| 编译报 `no member named 'nullptr_t'` / `<compare>` 之类的标准库错误 | 有东西把 `<emsdk>/cache/sysroot/include` 当成 `-I` 加进来了，劫持了标准头。**不要**加那个 include |
| `CMAKE_MINIMUM_REQUIRED` 相关报错 | CMake 太新，加 `-DCMAKE_POLICY_VERSION_MINIMUM=3.5` |
| 改了代码但浏览器行为没变 | `index.html` 需要手动 copy；另外确认 `locateFile` 的 cache-bust 生效（页面里用 `BUILD_TAG` 做了）。也可能需要强制刷新 |
| 反复重载后 WebGL 上下文耗尽 / `GLFW window create error` | 换一个干净的浏览器进程/会话 |
| 想让 mp4 / MPD 由 HTTP 服务器提供，而不是预加载进内存 | 见第 7 章。核心是在 `local_curl` 的 `open_resolved()` 里加同步 XHR（worker 里合法） |

---

## 7. 进阶：把视频内容改成 HTTP 加载（不再预加载 59 MB 进内存）

### 7.1 现在的做法

`--preload-file .../webcontent@/` 会把 `webcontent/` 里的每个文件
**原样拼进一个 `render.data`**（`file_packager` 的格式，文件内容首尾相接），
页面加载时由 `render.js` 一次性读进 **Emscripten 的 MEMFS**：

```
render.wasm   49.8 MB   只有代码，视频不在里面
render.data   59.2 MB   视频内容（MPD + tile 轨道），启动时整体载入 wasm 内存
```

> 所以严格说：**mp4 没有被"编进 wasm"**，而是打进 `render.data` 并**常驻在 wasm 堆内存里**。
> 这也是为什么 `.gitignore` 要排除 `*.data` —— 它是构建产物，不是一个需要版本管理的源文件。

`src/OmafDashAccess/local_curl/local_curl.cpp` 用 `fopen()` / `fread()` 从 MEMFS 里同步读，
上层 OMAF 的下载器代码完全不知道数据是从哪来的。

### 7.2 能不能改成 HTTP 服务？—— 能

关键前提是一个浏览器平台事实，这里**实测验证过**：

> **在 Web Worker 里，同步 XHR 是允许的**（在主线程才被限制）。
> 而 Emscripten 的 pthread 就是真正的 Web Worker。

实测（在本项目的页面上开一个 Worker 做同步 XHR）：

```json
{ "small": { "status": 200, "bytes": 5408, "ct": "text/html" }, "ok": true }
```

Emscripten 自己的惰性加载机制也基于同一事实，
`src/library_fs.js` 里的注释写得很直接：

```js
// Creates a file record for lazy-loading from a URL. XXX This requires a synchronous
// XHR, which is not possible in browsers except in a web worker!
createLazyFile: (parent, name, url, canRead, canWrite) => { ... }
```

也就是说：**"同步读"这个 API 形状可以原样保留**，不需要为了联网把整条 OMAF 读取链改成异步。

还有一个让事情变简单的观察：播放器实际只会读**小文件** ——

| 读的东西 | 大小 |
|---|---|
| `Test.mpd` | 113 KB |
| 每个 tile 分片 | 约 10–30 KB |
| init segment | 几 KB |

所以**整个文件 GET 下来**就够了，不需要 HTTP Range。
（OMAF 在续传路径上确实会设 `CURLOPT_RANGE`，但那可以在本地已有的缓存上切片满足，不必真的走网络 Range。）

### 7.3 做法 A（推荐）：给 `local_curl` 加一个 HTTP 后端

改动集中在 `local_curl.cpp` 的一个函数里 —— `open_resolved()`。
它现在只查 VFS；加上"查不到就去取"即可：

```
open_resolved(url):
    1. 在 IVF / MEMFS 里找（现有逻辑，保持不变）
    2. 命中 → 返回 FILE*，结束
    3. 未命中且处于 HTTP 模式 → 把 url 映射成一个 HTTP 地址，同步 XHR 下载
    4. 把字节写进 MEMFS（FS.writeFile），并把路径记进缓存
    5. 回到第 1 步再 fopen 一次
```

伪代码（用 `EM_JS` 暴露一个同步取字节的函数）：

```cpp
// 返回 malloc 出来的 buffer 指针，长度通过 *out_len 带回；失败返回 nullptr。
EM_JS(void *, ivs_http_get_sync, (const char *url, int *out_len), {
  try {
    var x = new XMLHttpRequest();
    x.open('GET', UTF8ToString(url), false);   // false = 同步（worker 里合法）
    x.responseType = 'arraybuffer';
    x.send();
    if (x.status !== 200) return 0;
    var bytes = new Uint8Array(x.response);
    var ptr = _malloc(bytes.length);
    HEAPU8.set(bytes, ptr);
    setValue(out_len, bytes.length, 'i32');
    return ptr;
  } catch (e) { return 0; }
});
```

这个做法的好处：

* **上层 OMAF / 解码 / 渲染代码一行都不用改**（API 形状没变）；
* 不需要服务器支持 Range，只要普通 GET；
* 可以彻底去掉 `--preload-file`，**省掉 59 MB 常驻 wasm 内存**（改成按需，且只保留当前用到的分片）；
* 加一层缓存后，重复请求同一个分片不会重复下载；
* 换内容不用重新编译。

需要注意的：

* **仍然是同步阻塞**：worker 会卡在那次 XHR 上，但因为每个分片只有几十 KB，可以接受。
  这就是原来 `local_curl` 的语义，没有变坏。
* **失败要能报错**：网络错误要映射成 curl 的错误码（`CURLE_COULDNT_CONNECT` 之类），
  否则上层会一直重试。
* **地址映射**：`render.cpp` 里已有 `<url>` 配置和 `em_local_curl_set_root()`，
  可以把 root 从 `/Gaslamp` 换成一个 HTTP base，例如
  `em_local_curl_set_root("http://127.0.0.1:8123/Gaslamp")`，
  `candidate_paths()` 再把 `Test.mpd` / `Test_track33.20.mp4` 拼上去。
* **仍然需要 COOP/COEP**：跨源隔离是为了 `SharedArrayBuffer`（pthreads），
  和内容从哪来无关，所以 `tools/serve_wasm.py` 的两个响应头必须保留。

### 7.4 做法 B：用 Emscripten 的 `createLazyFile`

```cpp
// 必须从 pthread（worker）里调用
EM_ASM({
  FS.createLazyFile('/', 'Test_track33.20.mp4', '/Gaslamp/Test_track33.20.mp4', true, false);
});
```

它会先发一个**同步 HEAD** 拿长度，然后按 chunk 用 **Range** 请求按需加载。

* 优点：大文件友好，内存占用只跟访问范围有关。
* 缺点：
  * 需要服务器支持 **HEAD + Range** —— 当前的 `tools/serve_wasm.py` **不支持**
    （实测带 `Range` 头仍返回 `200` + 全量 59 MB，`Content-Range` 为空）；
  * 每个文件都要显式注册一次，路径映射得和 `local_curl` 的候选路径对齐；
  * 分片很小，用不上它的优势。

**做 A 就够，B 只在将来要串流大文件时才有意义。**

### 7.5 服务器要改什么

| 需求 | 做法 A | 做法 B |
|---|---|---|
| 普通 GET 静态文件 | ✅ 现在就有 | ✅ |
| COOP/COEP 响应头 | ✅ 现在就有 | ✅ |
| HEAD | 不需要 | **需要加** |
| Range (`206` + `Content-Range`) | **不需要** | **需要加** |
| 不再需要 `--preload-file` | 是 | 是 |
| 不再需要 `FORCE_FILESYSTEM` | 否（还要写 MEMFS） | 是 |

`tools/serve_wasm.py` 基于 Python 的 `http.server`，它本身不支持 Range。
如果要做 B，最省事的是换成支持 Range 的静态服务器（或给 handler 加 `send_head` 的 Range 分支）。

### 7.6 一个更省事的中间方案

不想改 C++ 的话，还有一个"半步"做法：**只预加载 MPD，其余走 HTTP**。
但它一样要解决"分片从哪来"的问题，所以本质上还是要落到做法 A 或 B。
真要省内存，直接做 A。

---

## 8. 已知限制

* **软解**：HEVC 全靠 CPU，8K 级别的画面帧率不高。原生的硬件解码路径（VAAPI / VideoToolbox）在 wasm 里没有。
* **内容必须是预打包的**：现在没有网络栈，播放器从 VFS 同步读文件。
  要播放任意 URL 需要另外实现 HTTP（`emscripten_fetch` 或一个 WebSocket→POSIX 代理）。
* **`local_curl` 是一个仿制的 curl 子集**，不是真 curl。
  它只实现 OMAF 用到的那部分 API，行为按本地文件场景简化。
* **`-g4` 还在**，`render.wasm` 体积偏大。
* **诊断代码还在树里**：`bigalloc_probe.cpp` 用 `emscripten_builtin_malloc/free` 接管了全局分配器做记账，
  对性能有影响；还有一处对 ≥512 KB 分配抓调用栈（限 40 次，打到 stderr）。
  正式发布建议把该文件从链接中去掉。
* **ffmpeg 库路径硬编码**在 `CMakeLists.txt` 里，换机器要改（见 1.7）。
* **emsdk 版本被钉死在 3.1.40**：`ffmpeg_wasm_lib` 里的 `.a` 是这个版本编的，
  升级 emcc 前需要先把 FFmpeg 库重编一遍。
* **`~/source/ffmpeg.wasm` 是你自己的 fork**（`Dockerfile`、`build/ffmpeg.sh`、`exe.sh` 是本地改动）。
  这个分叉是**有意的、不需要跟上游合并**：改动只是裁掉用不到的前置库、把 `make -j` 降成 `-j 2` 省内存，
  **不影响编出来的 ffmpeg 库的可用性**。把它当成一个"一次性编库工程"看待即可。
* **`libcurl.a` 还在 `ffmpeg_wasm_lib/lib/` 里但已无人使用**，可以删掉以免误导。
  同理 `~/source/curl_py/` 是已废弃的实验。

---

## 9. 一览：从零到跑起来

```bash
# 0) 环境
source ~/source/emsdk/emsdk_env.sh
export EM_CACHE=$PWD/.emcache

# 1) 内容（约 67 MB）
cd ~/source/Immersive-Video-Sample
tools/stage_content.sh

# 2) 配置 + 编译
mkdir -p src/build/client && cd src/build/client
emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5
make player -j8
cd ../../..

# 3) 同步页面
cp webpage/index.html src/build/client/player/app/index.html

# 4) 起服务
python3 tools/serve_wasm.py --root src/build/client/player/app --port 8123

# 5) 浏览器打开
#    http://127.0.0.1:8123/index.html
#    点一下画面锁定鼠标，然后按住左键拖动环视
```
