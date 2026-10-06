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
| ffmpeg.wasm 构建配方 | fork，`main` @ `e2dd60e` | **`tools/ffmpeg-wasm/`（已 vendored）** | 另有一份完整 clone 在 `~/source/ffmpeg.wasm`；重编只需本仓库 |
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

### 1.4 FFmpeg wasm 库原本是怎么编出来的（Docker 交叉编译）

**构建配方已经 vendored 进本仓库**：`tools/ffmpeg-wasm/`（Dockerfile、`build/*.sh`、
`exe.sh`、Makefile、LICENSE），来源与改动说明见 [tools/ffmpeg-wasm/README.md](tools/ffmpeg-wasm/README.md)。
**要重编 FFmpeg 不需要再去找别的仓库** —— 源码由脚本直接从上游克隆，
配方就在本仓库里。

原始构建工程在 `~/source/ffmpeg.wasm`。**它是有 `.git` 的**，而且已推送到你的 fork：

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
  zlib、libwebp、freetype、fribidi、harfbuzz、libass、zimg）**全部注释掉**；
* 把 `ffmpeg-wasm-builder` 和 `exportor` 两个阶段也注释掉了 —— 这次构建
  **只产出原生静态库**，不产出 `ffmpeg-core.js`；
* 所有 `ADD` 的 URL 都走 `https://ghfast.top/github.com/...` 镜像。

### 1.5 为什么当时用了 OrbStack —— 而且它其实不是必需的

**为什么会有 Docker**：`ffmpeg.wasm` 这个上游项目的构建系统本来就是
`docker buildx build`（见它的 `Makefile`），Dockerfile 里 `FROM emscripten/emsdk:3.1.40`。
你沿用了这套流程，所以 ffmpeg 就编在容器里。**这是继承来的做法，不是产物本身的要求。**

是否真的用了 OrbStack，有据可查：

```bash
docker context ls
# orbstack *      unix:///Users/hasee/.orbstack/run/docker.sock     ← 当时激活的就是它
docker info --format '{{.ServerVersion}} | {{.OperatingSystem}}'
# 27.5.1 | OrbStack
docker buildx ls
# orbstack*  running  v0.18.2  linux/amd64 (+2), linux/arm64, ...
```

**为什么它不必需**：

* emcc 在 macOS 上原生可用，产物同样是 wasm32；
* x264、x265、FFmpeg 用的都是各自的 configure / CMake，
  **不涉及 autoconf 和 GNU libtool**；
* 三个库都是 `--disable-asm`，所以连 nasm/yasm 都不需要；
* 唯一真正的要求是**目标特性**：这些 `.a` 会被链进一个 `-pthread`（共享内存）模块，
  所以必须带 `atomics` + `bulk-memory`。这是编译参数问题，和 Linux 无关。

实测（写这份文档时做的）：

| | 容器（OrbStack） | 原生（本机 emcc） |
|---|---|---|
| `libx264.a` | 2856446 字节 | **2856446 字节，SHA256 完全相同** |

> 也就是说，同一版 emcc、同一组参数，**容器和 macOS 产出逐字节一致的库**。
> Docker 在这里提供的是"环境一致性"这一层便利，而不是能力。

**但播放器本身的构建和运行从来都不需要 Docker**：

| 阶段 | 需要 Docker / OrbStack 吗 |
|---|---|
| 编 FFmpeg wasm 静态库（一次性） | 用原来的 Dockerfile 的话需要；**用 1.6 的脚本不需要** |
| 编播放器、跑播放器 | **不需要** |

### 1.6 不用 Docker：原生构建（推荐）

`tools/build_ffmpeg_wasm.sh` 把 `tools/ffmpeg-wasm/Dockerfile` 里那几个阶段原样搬到本机，
用你 emsdk 里的 emcc，**不需要 Docker/OrbStack，也不需要别的仓库**：

```bash
cd ~/source/Immersive-Video-Sample
tools/build_ffmpeg_wasm.sh --jobs 8
```

也可以走 CMake：

```bash
cd src/build/client && make ffmpeg-wasm
```

产物默认写到 **`<repo>/build/ffmpeg-wasm/prefix`**（`build/` 已被 `.gitignore` 排除），
**不会覆盖你现有的 `~/source/ffmpeg_wasm_lib`**。

然后用它来编播放器：

```bash
emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DIVS_FFMPEG_WASM_LIB_DIR=$PWD/../../build/ffmpeg-wasm/prefix \
    -DIVS_FFMPEG_WITH_X265=OFF
make player -j8
```

脚本要点：

* **默认不编 x265**。播放器只**解码** HEVC，libx265 是编码器，
  播放器源码里对 x265 有**零引用** —— 它是纯累赘，而且是最慢的一部分。
  需要的话加 `--with-x265`（x265 3.4 把 CMP0025/CMP0054 钉在 OLD，
  CMake 4 会直接报错，脚本会自动打一个小补丁并打印说明）。
* 源码按 Dockerfile 里的分支/tag 浅克隆到 `build/ffmpeg-wasm/src/`
  （x264 `4-cores`、x265 `3.4`、FFmpeg `n5.1.4`），默认走 `ghfast.top` 镜像，
  可用 `GITHUB_MIRROR=` 覆盖。
* `CFLAGS` 里带 `-matomics -mbulk-memory`，这是能链进共享内存模块的前提。
* 已经装好的阶段会跳过，重跑很快；要全清用 `--clean`。

**实测**（Apple M4 Pro，`--jobs 8`）：

```
x264 + FFmpeg（不含 x265）   约 6 分钟
产物                          build/ffmpeg-wasm/prefix/
libavcodec.a                  19770176 字节
目标特性                      atomics+ bulk-memory+ mutable-globals+ sign-ext
```

用这套库编出来的播放器**正常完整播放**（截图 `porting-evidence/native_ffmpeg_playback.png`），
`render.wasm` 也从 49.8 MB 降到 **40.75 MB**（因为去掉了 x265、libvpx、lame、ass、webp）。

### 1.7 那次 libcurl 的尝试（`~/source/curl_py/`）

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

### 1.8 换机器时的检查清单

按顺序确认：

1. `emsdk` 装好且是 **3.1.40**：`emcc --version`
2. FFmpeg wasm 库二选一：
   * 复用现成的 `~/source/ffmpeg_wasm_lib`，或
   * 用 `tools/build_ffmpeg_wasm.sh` 现场编一份（**不需要 Docker**）
3. 用 `-DIVS_FFMPEG_WASM_LIB_DIR=<路径>` 指向它；如果那份没有 x265，再加
   `-DIVS_FFMPEG_WITH_X265=OFF`
4. 原始视频素材在 `~/source/IVS_webpage/gaslamp/Gaslamp`（256 MB / 14449 个文件）
5. `cmake` ≥ 3.5、`python3` 可用
6. 一个支持 WebGL2 + SharedArrayBuffer 的桌面浏览器

## 2. 内容准备

播放器需要的内容**不在这个仓库里**（视频文件太大）。
原始素材在 `~/source/IVS_webpage/gaslamp`，用脚本把它"搬"到仓库的 `webcontent/`。

`webcontent/` 有两种用法：默认被 `--preload-file` 打进 `render.data`；
也可以由 web 服务器直接提供（`IVS_PRELOAD_CONTENT=OFF`，见第 7 章）。
**两种模式都用同一个 `webcontent/` 目录**，准备步骤完全一样。

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
| `?contentBase=<url>` | 改内容来源（HTTP 模式，见第 7 章）。例如 `?contentBase=http://192.168.1.10:9000/Gaslamp` |

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
| 想让 mp4 / MPD 由 HTTP 服务器提供，而不是预加载 | 见第 7 章。用 `-DIVS_PRELOAD_CONTENT=OFF` 构建，并用 `serve_wasm.py --content webcontent` 起服务 |
| HTTP 模式下一片漆黑、日志里 `httpFetches` 一直是 0 | 内容服务器没起或路径不对。看 `?verbose=1` 里有没有 `cannot open '...' and HTTP fetch from base '...' failed (HTTP 404)` |

---

## 7. 内容来源：预加载 vs HTTP 服务

播放器有两种内容来源模式，**源码完全相同**，只差一个 CMake 开关：

|  | 预加载（默认） | HTTP |
|---|---|---|
| 构建参数 | `IVS_PRELOAD_CONTENT=ON` | `-DIVS_PRELOAD_CONTENT=OFF` |
| 内容存放 | `--preload-file` 打进 `render.data`（59 MB） | `webcontent/` 由 web 服务器提供 |
| 加载方式 | 启动时整体载入 Emscripten 的 MEMFS | 按需 HTTP 取，读完即释放 |
| 需要内容服务器 | 不需要 | 需要 |
| MEMFS 里的内容 | **57 MB**（`/Gaslamp` 下 6000+ 个文件） | **0.1 MB**（只有 `Test.mpd`） |
| 占的是哪块内存 | **浏览器的 JS 堆** | 几乎没有 |
| 占多少 wasm 线性内存 | **0** | **0**（两种模式一样） |
| 换内容要重新编译吗 | 要 | 不要 |
| 适合 | 单文件部署、离线演示 | 内容大、内容会更新、想少占标签页内存 |

> ⚠️ **一个容易搞错的地方**：`--preload-file` 的内容**不在 wasm 线性内存里**。
> `file_packager` 交给 MEMFS 的是一个由 JS ArrayBuffer 构造的 `Uint8Array`
> （见生成代码里的 `new Uint8Array(arrayBuffer)` + `FS_createDataFile`），
> 也就是**浏览器的 JS 堆**。所以切到 HTTP 模式**并不会**给你省出 wasm 堆空间
> （`MAXIMUM_MEMORY=4GB` 那边的压力完全不变），它省的是标签页的 JS 内存。
> 这一点是实测出来的，见 7.5。

两种模式下都可以用 URL 参数 `?contentBase=<url>` 覆盖运行时地址。

### 7.1 用 HTTP 模式构建

```bash
cd ~/source/Immersive-Video-Sample
source ~/source/emsdk/emsdk_env.sh
export EM_CACHE=$PWD/.emcache          # 注意顺序：先 source 再 export

mkdir -p src/build/client && cd src/build/client
emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DIVS_PRELOAD_CONTENT=OFF
make player -j8
```

配置阶段应该看到：

```
-- IVS: NOT preloading content; it must be served over HTTP (set <contentBaseUrl> or ?contentBase=...)
```

构建产物里**不再有 `render.data`**，`render.js` 也从 845 KB 降到 265 KB。

切回预加载模式就是把开关改成 `ON` 再配置一次：

```bash
emcmake cmake ../.. -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DIVS_PRELOAD_CONTENT=ON
make player -j8
```

> **注意**：`player/app` 是被 `src/CMakeLists.txt` 里的一个 `ADD_CUSTOM_TARGET`
> **另起一次嵌套 cmake 配置**构建的，所以开关必须在 `src/CMakeLists.txt` 里显式转发
> （已经做好了）。只给最外层传参而不转发是不会生效的。

### 7.2 起内容服务器

`tools/serve_wasm.py` 现在可以同时服务"播放器产物"和"视频内容"两个目录：

```bash
python3 tools/serve_wasm.py \
    --root src/build/client/player/app \
    --content webcontent \
    --port 8123
```

启动时会打印：

```
serving .../player/app at http://127.0.0.1:8123/
content .../webcontent/Gaslamp at http://127.0.0.1:8123/Gaslamp/
  -> use ?contentBase=http://127.0.0.1:8123/Gaslamp
```

`--content` 既可以给"装着 `Gaslamp/` 的目录"（`webcontent`），也可以直接给 `webcontent/Gaslamp`，
脚本会自动识别。内容目录默认发布在 `/Gaslamp`，可用 `--content-prefix` 改。

COOP/COEP 两个头照旧会带上 —— 那是给 `SharedArrayBuffer` 用的，和内容从哪来无关。

### 7.3 零配置

如果既没写 `<contentBaseUrl>`，也没传 `?contentBase=`，播放器会**默认用页面自己的源**：

```
<location.origin>/Gaslamp
```

所以上面那条命令之后，直接打开 `http://127.0.0.1:8123/index.html` 就能播，不用加任何参数。
要指向别处（另一个端口、CDN、另一台机器）再显式传：

```
http://127.0.0.1:8123/index.html?contentBase=http://192.168.1.10:9000/Gaslamp
```

也可以写进 `config.xml`：

```xml
<contentBaseUrl>http://192.168.1.10:9000/Gaslamp</contentBaseUrl>
```

（`config.xml` 是 `render.cpp` 里内嵌的模板，运行时写到虚拟文件系统再读回来。）

### 7.4 实现原理

改动集中在两处：`local_curl.cpp` 加了一个 HTTP 后端，`render.cpp` 打通配置。

**（1）为什么可以保持同步 API**

OMAF 的下载器要求 `curl_easy_perform()` / `curl_multi_perform()` 返回时传输已经完成，
所以整条链条是同步的。好消息是**这个形状可以原样保留**：

> **在 Web Worker 里，同步 XHR 是允许的**；而被限制的只有 document（主线程）。
> Emscripten 的 pthread 就是真正的 Web Worker。

Emscripten 自己的惰性加载机制基于同一事实，`src/library_fs.js` 里写得很直白：

```js
// XXX This requires a synchronous XHR, which is not possible in browsers
// except in a web worker!
createLazyFile: (parent, name, url, canRead, canWrite) => { ... }
```

**（2）取数据：`open_resolved()` 里加一次回退**

它原本只查虚拟文件系统。现在查不到、且配置了 base URL 时，
用 `EM_JS` 暴露的 `ivs_http_get_sync()` 做一次同步 GET，把结果包成内存文件返回：

```cpp
FILE *open_resolved(url, path_out) {
    1. 路径缓存命中        -> fopen
    2. VFS 候选路径        -> fopen（预加载内容走这里，优先）
    3. open_over_http(url) -> 同步 XHR -> fmemopen()
}
```

**上层 OMAF / 解码 / 渲染一行都没改**，因为返回的还是一个普通 `FILE*`。

**（3）为什么用 `fmemopen` 而不是写进 MEMFS**

写进 MEMFS 会让文件永久驻留 —— 最后又变成 67 MB 常驻，等于白做。
`fmemopen()` 把响应体包成一个内存流，读完 `fclose` 就释放：
`local_curl.cpp` 里维护了 `FILE* -> buffer` 的映射，统一在 `close_file()` 里释放
（`perform_transfer` 的所有 `fclose` 都改走它了）。

顺带避免了并发问题：OMAF 有多个下载线程，写 MEMFS 需要为每个临时文件生成唯一名字，
用内存流就没有这个问题。

**（4）MPD 是个例外**

MPD **不经过 curl** —— `OmafXMLParser::Generate()` 用的是
`tinyxml2::XMLDocument::LoadFile()`，一次普通的文件读取。所以在 HTTP 模式下，
创建播放器之前必须先把 MPD 放进虚拟文件系统：

```cpp
em_local_curl_prefetch(renderConfig.url);
```

只有这一个文件（113 KB）。实现上有个细节：**主线程不允许给同步请求设置
`responseType`**（规范限制，会抛 `InvalidAccessError`），所以这个 prefetch
内部起一个辅助线程去发请求再 `join`，对调用方仍然是同步的。

### 7.5 实测结果

#### HTTP 模式跑起来的样子

`IVS_PRELOAD_CONTENT=OFF`，内容由 `serve_wasm.py --content webcontent` 提供，
页面地址不带任何参数（走 7.3 的默认值）：

```
httpFetches   125 -> 613 -> 997        逐段增长，每段一次请求
httpMB        1.4 -> 8.2 -> 13         累计取回
httpFail      0
decoders      2
errors        0
```

画面正常播放（截图 `porting-evidence/http_mode_playback.png`，本地文件未入库）。

#### A/B：到底省了什么

同一台机器、同一个页面，只切换 `IVS_PRELOAD_CONTENT`，加载后约 70 秒各测一次：

| 指标 | 预加载 ON | HTTP OFF |
|---|---|---|
| `/Gaslamp` 条目数 | 6051 | **3**（`.` `..` `Test.mpd`） |
| `/Gaslamp` 内容字节 | **57 MB** | **0.1 MB** |
| `em_probe_live_kb()`（wasm 分配器存活） | 245684 KB | 244871 KB |
| `Module.HEAPU8.length` | 369 MB | 369 MB |
| `httpFetches` | 0 | 997 |

结论有两层，第二层是必须说清楚的：

1. **内容确实不再驻留**：从页面里清点 MEMFS，`/Gaslamp` 下 6000+ 个文件、57 MB，
   变成只剩一个 113 KB 的 MPD。分片是 `fmemopen` 内存流，传输结束就释放。
2. **省的是 JS 堆，不是 wasm 堆**：`liveKB` 只差 813 KB，`HEAPU8.length` 完全相同。
   这和 7.4 的原理一致 —— 预加载数据是 JS ArrayBuffer，从来没进过 wasm 线性内存。
   所以如果你的动机是"缓解 4 GB 的 wasm 堆压力"，**这个开关帮不上忙**；
   它的价值是少传 57 MB、少占标签页内存、以及换内容不用重编译。

> 判断内存时不要用 `Module.HEAPU8.length`。那是 wasm 内存的**大小**，按几何步长增长，
> 两种模式会停在同一个数值上。要看真实占用用 `Module.ccall('em_probe_live_kb', ...)`
> （见 5.3），或者像上面这样直接清点 MEMFS。

### 7.6 需要注意

* **失败时的表现**：内容 URL 不对会报
  `cannot open '...' and HTTP fetch from base '...' failed (HTTP 404)`，
  在 `?verbose=1` 下能看到。不会再出现"什么都不播也不报错"。
* **同步阻塞**：每个分片会阻塞所在 worker 一次 XHR。分片只有 10–30 KB，
  和原来读 VFS 的语义一致，没有变坏。
* **仍然需要 COOP/COEP**：跨源隔离是为 `SharedArrayBuffer`（pthreads），
  不是为内容。
* **跨域内容**：如果内容在别的源上，那个源也要发 `Cross-Origin-Resource-Policy`
  或 CORS 头，否则 COEP 会拦掉。
* **`server/serve_wasm.py` 现在支持 Range**（返回 `206` + `Content-Range`），
  但 HTTP 模式**并不需要**它 —— 分片很小，一次 GET 就取完。
  加它是为了将来若改用 `FS.createLazyFile` 时可用。

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
#     加 -DIVS_PRELOAD_CONTENT=OFF 则改为 HTTP 模式（见第 7 章）
make player -j8
cd ../../..

# 3) 同步页面
cp webpage/index.html src/build/client/player/app/index.html

# 4) 起服务
#    预加载模式：内容已在 render.data 里，--content 可以省略
python3 tools/serve_wasm.py --root src/build/client/player/app --port 8123
#    HTTP 模式：必须把内容目录也服务出去
# python3 tools/serve_wasm.py --root src/build/client/player/app \
#         --content webcontent --port 8123

# 5) 浏览器打开
#    http://127.0.0.1:8123/index.html
#    点一下画面锁定鼠标，然后按住左键拖动环视
```
