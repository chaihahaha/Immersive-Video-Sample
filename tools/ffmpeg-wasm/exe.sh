bash -x /src/build.sh \
      --enable-gpl \
      --enable-libx264 \
      --enable-libx265 \
      --enable-libmp3lame \
      --enable-libtheora \
      --enable-libvorbis \
      --enable-libopus \
      --enable-zlib \
      --enable-libwebp \
      --enable-libfreetype \
      --enable-libfribidi \
      --enable-libass \
      --enable-libzimg 

# Build ffmpeg.wasm
FROM ffmpeg-builder AS ffmpeg-wasm-builder
COPY src/bind /src/src/bind
COPY src/fftools /src/src/fftools
COPY build/ffmpeg-wasm.sh build.sh
# libraries to link
ENV FFMPEG_LIBS="-lx264  -lx265  -lvpx  -lmp3lame  -logg  -ltheora  -lvorbis  -lvorbisenc  -lvorbisfile  -lopus  -lz  -lwebpmux  -lwebp  -lsharpyuv  -lfreetype  -lfribidi  -lharfbuzz  -lass  -lzimg"
RUN mkdir -p /src/dist/umd && bash -x /src/build.sh \
      ${FFMPEG_LIBS} \
      -o dist/umd/ffmpeg-core.js
RUN mkdir -p /src/dist/esm && bash -x /src/build.sh \
      ${FFMPEG_LIBS} \
      -sEXPORT_ES6 \
      -o dist/esm/ffmpeg-core.js

# Export ffmpeg-core.wasm to dist/, use `docker buildx build -o . .` to get assets
FROM scratch AS exportor
COPY --from=ffmpeg-wasm-builder /src/dist /dist
