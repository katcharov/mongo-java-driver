## The problem: left-nesting in `thenRun`

The chain is built as:

```
c1000 = c999.thenRun(body_1000) = (c) -> c999.unsafeFinish((r,e) -> body_1000.finish(c))
c999  = c998.thenRun(body_999)  = (c) -> c998.unsafeFinish((r,e) -> body_999.finish(c))
...
c1    = b.thenRun(body_1)       = (c) -> b.unsafeFinish((r,e) -> body_1.finish(c))
b     = beginAsync()            = (c) -> c.complete(c)
```

When `c1000.finish(finalCb)` executes, it calls `c999.unsafeFinish(...)`, which calls
`c998.unsafeFinish(...)`, ..., which calls `b.unsafeFinish(...)`. This creates **~1000 stack
frames** just to *reach* `beginAsync`. None of these frames return until the entire chain
completes — the stack trace from the test confirms this:

```
  1.  test lambda (body_1 running)
  2.  AsyncSupplier.finish
  3.  thenRun$1 (runnable.finish(c))       <- body_1 invoked
  4.  SingleResultCallback.complete
  5.  beginAsync lambda (c.complete(c))     <- beginAsync fires
  6.  thenRun$2 (this.unsafeFinish)  +
  7.  thenRun$2 (this.unsafeFinish)  |
  ...                                | <- ~1000 frames of left-nesting
                                     |    unwinding c1000 -> c999 -> ... -> c1
  1005. thenRun$2 (this.unsafeFinish) +
  1006. AsyncSupplier.finish
  1007. testStackDepthBounded          <- entry point
```

This is the stack for **body_1** (the first body to execute). It's already ~1007 MongoDB frames
deep. When body_1 completes synchronously via `c.complete(c)`, it fires body_2 *on top of these
same frames*, making the stack even deeper for each subsequent body. The JVM's
`MaxJavaStackTraceDepth` (default 1024) truncates `getStackTrace()`, so the test sees a flat
1024 for all iterations.

## Why `loopWhile` doesn't have this problem

`loopWhile` uses a flat `while(true)` loop for synchronous completions and a CAS-based
yield/resume for async ones — the loop body always runs at the same stack depth. But `thenRun`
composes via nesting: each `.thenRun()` wraps the previous chain in another lambda that calls
`this.unsafeFinish(...)`, creating O(N) stack depth proportional to the chain length.

## Summary

The issue isn't in `loopWhile` — it's in `thenRun`. There's no trampoline or iterative
flattening in `thenRun`, so a chain of N `thenRun` calls requires O(N) stack frames to unwind
before any body even starts executing.
