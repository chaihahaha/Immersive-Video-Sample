# Immersive Video Sample —— WebAssembly 移植：环境配置 / 编译 / 部署 / 使用

本文档描述如何把 `src/player/app/linux` 这个 OMAF 全景播放器编译成 WebAssembly，
在浏览器里播放 `Gaslamp` 这段 MPEG-DASH tiled 360 视频。

> 这段移植的历史背景、失败原因复盘、以及内存问题的根因分析，
> 见 [PORTING_POSTMORTEM.md](PORTING_POSTMORTEM.md)。本文只讲**怎么跑起来**。

---

## 0. 一句话总结

浏览器里跑的是一个 **pthreads + WebGL2 的 wasm 构建**：

* 视频内容通过 `--preload-file` 打进 Emscripten 虚拟文件系统（VFS），
  原始的 libcurl 被 [src/OmafDashAccess/local_curl/local_curl.cpp](src/OmafDashAccess/local_curl/local_curl.cpp)
  替换成**同步读 VFS**；
* HEVC 解码是 **FFmpeg 5.1.4 编译出的 wasm 软解**（无硬件加速）；
* 渲染用 **WebGL2**，而且**所有 GL 调用都在主线程**（帧数据从解码线程拷到主线程再上传）；
* 因为用了 pthreads，页面**必须处于跨源隔离（cross-origin isolated）状态**才能拿到 `SharedArrayBuffer`。

---

## 1. 环境准备

### 1.1 必需组件

| 组件 | 版本 / 路径 | 说明 |
|---|---|---|
| Emscripten SDK | 3.1.40，`~/source/emsdk` | 其他版本未验证；3.1.40 的 libc++ 与本文档的构建参数配套 |
| FFmpeg wasm 静态库 | `~/source/ffmpeg_wasm_lib` | 预编译好的 `libavcodec.a` 等，**路径在 CMakeLists 里是写死的** |
| CMake | ≥ 3.5（本机 4.4.3） | 源码里 `CMAKE_MINIMUM_REQUIRED` 已从 2.8 提到 3.5，否则 CMake 4 会直接报错 |
| Python 3 | 任意 | 只用来跑本地静态服务器 |
| 浏览器 | Chrome / Chromium（桌面版） | 需要 WebGL2 + SharedArrayBuffer |

### 1.2 激活 emsdk

```bash
source ~/source/emsdk/emsdk_env.sh
emcc --version        # 应显示 3.1.40
```

> **重要**：Emscripten 默认把缓存放在 `~/.emscripten_cache`。
> 如果在受限环境里该目录不可写，需要把它指到工作区内：
>
> ```bash
> export EM_CACHE=$PWD/.emcache
> ```
>
> 本文档后续命令都假定你已经设好这个变量。

### 1.3 关于 FFmpeg 静态库

`src/player/app/CMakeLists.txt` 里对 ffmpeg 的头文件和库路径是**绝对路径硬编码**的：

```cmake
target_include_directories(render PRIVATE /Users/hasee/source/ffmpeg_wasm_lib/include ...)
SET(LINK_LIB ${LINK_LIB} MediaPlayer ... /Users/hasee/source/ffmpeg_wasm_lib/lib/libavcodec.a ...)
```

换机器时需要把这些路径改成你自己的。这个库的性质是：

* FFmpeg **5.1.4**，用同一个 emsdk 3.1.40 编译；
* `-pthread` + atomics；
* `CONFIG_HEVC_DECODER 1`；
* **没有** VAAPI / VideoToolbox / MediaCodec —— 纯软解。

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

---

## 7. 已知限制

* **软解**：HEVC 全靠 CPU，8K 级别的画面帧率不高。原生的硬件解码路径（VAAPI / VideoToolbox）在 wasm 里没有。
* **内容必须是预打包的**：现在没有网络栈，播放器从 VFS 同步读文件。
  要播放任意 URL 需要另外实现 HTTP（`emscripten_fetch` 或一个 WebSocket→POSIX 代理）。
* **`local_curl` 是一个仿制的 curl 子集**，不是真 curl。
  它只实现 OMAF 用到的那部分 API，行为按本地文件场景简化。
* **`-g4` 还在**，`render.wasm` 体积偏大。
* **诊断代码还在树里**：`bigalloc_probe.cpp` 用 `emscripten_builtin_malloc/free` 接管了全局分配器做记账，
  对性能有影响；还有一处对 ≥512 KB 分配抓调用栈（限 40 次，打到 stderr）。
  正式发布建议把该文件从链接中去掉。
* **ffmpeg 库路径硬编码**在 `CMakeLists.txt` 里。

---

## 8. 一览：从零到跑起来

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
