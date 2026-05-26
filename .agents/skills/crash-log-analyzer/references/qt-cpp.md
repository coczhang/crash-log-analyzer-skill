# Qt and C++ Crash Patterns

Read this when the crash involves Qt, QObject/QThread lifecycle, GUI thread misuse, queued connections, object ownership, C++ memory corruption, wild pointers, out-of-bounds writes, double frees, races, or deadlocks.

## Qt Facts to Establish

- Which thread owns each QObject: `obj->thread()` and current thread ID.
- Whether a thread has a running event loop.
- Parent-child ownership and destruction order.
- Whether pending queued signals can outlive sender/receiver assumptions.
- Whether lambdas capture `this`, references, raw buffers, or stack objects used asynchronously.
- Whether duplicate connections or repeated starts can cause repeated deletes/stops.

## High-Probability Qt Failure Patterns

- QWidget or GUI API used from a worker thread.
- QObject moved to a thread but created children/timers/sockets before `moveToThread()`, leaving children in the wrong thread.
- `delete` used across thread boundaries instead of `deleteLater()` while the target thread event loop is alive.
- Object destroyed while queued signal/lambda still captures raw `this`.
- `QThread` destroyed while still running.
- Calling `wait()`, `join()`, or blocking RPC from the same thread.
- Blocking the GUI/event loop, causing watchdog heartbeat timeout.
- `Qt::DirectConnection` accidentally crossing threads.
- Repeated setup causing duplicate signal connections and double execution.

## Safer QThread Shutdown Pattern

```cpp
connect(thread, &QThread::finished, worker, &QObject::deleteLater);

worker->moveToThread(thread);
thread->start();

// Shutdown from a different controlling thread.
QMetaObject::invokeMethod(worker, "stop", Qt::QueuedConnection);
thread->quit();
if (!thread->wait(5000)) {
    // Log and escalate; avoid deleting running thread-owned objects directly.
}
```

Do not call `thread->wait()` from the same `thread`. Check:

```cpp
Q_ASSERT(QThread::currentThread() != thread);
```

## Safer Async Captures

Prefer guarded captures for QObject receivers:

```cpp
QPointer<MyObject> guard(this);
QMetaObject::invokeMethod(target, [guard] {
    if (!guard) {
        return;
    }
    guard->doWork();
}, Qt::QueuedConnection);
```

Avoid capturing stack references in delayed callbacks:

```cpp
// Risky: value may be gone when the callback runs.
connect(reply, &QNetworkReply::finished, this, [&local] { use(local); });
```

## C++ Memory Corruption Checks

- Null pointer dereference.
- Use-after-free and stale callback.
- Double delete, invalid free, mixed allocator/CRT.
- Buffer overflow or off-by-one write.
- Iterator/reference invalidation after vector/string/map mutation.
- Reference to temporary or local object escaping its scope.
- Data race on ownership, container, ref-count, or frame buffer.
- `std::thread` destructor called while joinable.
- Static destruction order: singleton/logging/Qt objects used after teardown.

## Deadlock and Hang Checks

- Thread A waits for thread B while B emits a blocking queued call to A.
- GUI thread waits for worker completion while worker waits for GUI callback.
- Mutex acquired in signal handler/logging/destructor path.
- `BlockingQueuedConnection` used when sender and receiver may share the same thread.
- Watchdog heartbeat runs on the blocked event loop instead of an independent thread/process.

## Useful Instrumentation

Add thread IDs and object addresses to logs:

```cpp
qSetMessagePattern("%{time yyyy-MM-dd hh:mm:ss.zzz} [%{threadid}] %{type} %{category}: %{message}");
```

Trace destruction:

```cpp
connect(obj, &QObject::destroyed, obj, [](QObject *o) {
    qInfo() << "destroyed" << o << "thread" << QThread::currentThread();
});
```

Add affinity assertions around risky APIs:

```cpp
Q_ASSERT(obj->thread() == QThread::currentThread());
Q_ASSERT(qApp->thread() == QThread::currentThread());
```

Use sanitizers where feasible:

```bash
-fsanitize=address,undefined
-fsanitize=thread
```

On Windows, also consider Application Verifier, page heap, and `/RTC` for debug builds.

