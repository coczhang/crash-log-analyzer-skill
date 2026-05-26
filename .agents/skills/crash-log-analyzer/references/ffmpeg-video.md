# FFmpeg and Video Rendering Crashes

Read this when the crash involves FFmpeg, decoding/encoding, hardware acceleration, pixel conversion, Qt video rendering, GPU device loss, render threads, or frame-buffer lifetime.

## Evidence to Collect

- FFmpeg version/build configuration and whether DLLs/shared objects match headers.
- Decoder/encoder name, hardware device type, pixel format, width/height, time base, color format.
- Whether frame size or pixel format changes during the stream.
- Thread model: decode thread, upload/render thread, GUI thread, and ownership handoff.
- Exact ownership rules for each `AVPacket`, `AVFrame`, `AVBufferRef`, `SwsContext`, `AVCodecContext`, and wrapped Qt frame/image.
- GPU/driver messages around device reset, context loss, or hardware transfer failure.

## High-Probability Failure Patterns

- `AVPacket` or `AVFrame` reused after `av_packet_unref()` or `av_frame_unref()`.
- `AVFrame*` freed while a Qt wrapper, renderer, or async upload still references its data.
- Missing `av_frame_ref()` or `av_packet_ref()` when handing data across threads.
- Confusing `av_frame_unref()` with `av_frame_free()`.
- `SwsContext` reused after width/height/pixel-format changes.
- CPU code directly reads hardware frames without successful `av_hwframe_transfer_data()`.
- Pixel format mismatch or wrong plane/stride assumptions.
- Encoder receives odd dimensions or unsupported pixel format.
- Rendering occurs on the wrong Qt thread or wrong graphics context.
- GPU device/context is destroyed before queued render/upload work drains.

## Ownership Rules

- Treat `AVFrame` and `AVPacket` as ref-counted containers whose referenced buffers may outlive the struct only if explicitly referenced.
- When a frame crosses thread or async boundaries, use `av_frame_ref()` into a destination frame and unref/free it after the consumer finishes.
- Do not wrap raw FFmpeg plane pointers into `QImage`, `QVideoFrame`, or custom buffers unless the wrapper owns a reference that keeps the underlying memory alive.
- Reset conversion/scaling state on stream parameter changes.

Example guarded handoff:

```cpp
AVFrame *owned = av_frame_alloc();
if (av_frame_ref(owned, decoded) < 0) {
    av_frame_free(&owned);
    return;
}

enqueueForRender(owned, [](AVFrame *frame) {
    av_frame_free(&frame);
});
```

## Hardware Frames

Check every transfer:

```cpp
int rc = av_hwframe_transfer_data(cpuFrame, hwFrame, 0);
if (rc < 0) {
    // Log av_err2str(rc), source/destination formats, and skip this frame.
    return;
}
```

Validate:

- `frame->format` is the expected hardware pixel format before transfer.
- Destination CPU frame is allocated and writable when required.
- Device context outlives decoder and all in-flight frames.
- Reset device/decoder cleanly after GPU reset or display sleep/wake.

## Qt Rendering Notes

- Do UI and QWidget work only on the GUI thread.
- Do OpenGL/QRhi/D3D work only with the owning context current on the correct thread.
- Avoid handing a `QImage` built over external memory to another thread unless the backing store lifetime is explicit and synchronized.
- Drain queued render work before destroying decoder, frame pool, graphics context, or widget.

