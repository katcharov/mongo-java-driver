# Plan: Make AsyncRunnable.loopWhile() Non-Blocking

## Context

The current `loopWhile()` implementation in `AsyncRunnable.java` uses a `while(true)` loop that continues synchronously when callbacks complete immediately. This was an intentional optimization to avoid creating thousands of Runnable objects for fast, synchronous operations.

**The Problem:** When many consecutive synchronous iterations occur (e.g., retry loops that fail immediately), the thread blocks indefinitely without yielding, violating async guarantees and potentially causing thread starvation.

**Why Change is Safe:** Test investigation reveals that tests verify correctness, event ordering, and exception handling, but do NOT verify non-blocking behavior. Tests pass with both same-thread and separate-thread executors. This gives us freedom to optimize the implementation without breaking tests.

## Recommended Approach: Depth-Based Trampolining

Add a counter to track consecutive synchronous iterations. After N iterations (recommended: 100), force async scheduling via `CompletableFuture.runAsync()` to yield the thread. This preserves the performance optimization for short loops while guaranteeing non-blocking behavior for long-running loops.

### Why This is Best

| Criteria | Assessment |
|----------|------------|
| **API Changes** | None - existing code unchanged |
| **Test Impact** | All tests pass without modification |
| **Performance** | Preserves optimization for loops < 100 iterations |
| **Non-blocking** | Guarantees thread yield every 100 iterations |
| **Complexity** | Low - minimal code change, easy to understand |
| **Dependencies** | Uses JDK built-in `CompletableFuture.runAsync()` |

### Alternative Approaches Considered (and Rejected)

1. **Recursive callbacks** - Doesn't solve blocking, worse performance
2. **Add executor parameter** - Too invasive, breaks API compatibility
3. **Continuation queue** - Overly complex for the problem
4. **Thread.yield()** - Not guaranteed to yield, insufficient solution
5. **Accept current design** - Violates async contract, unacceptable

## Implementation Details

**File:** `/Users/maxim.katcharov/code/mongo-java-driver/driver-core/src/main/com/mongodb/internal/async/AsyncRunnable.java` (lines 212-274)

**Changes to `loopWhile()` method:**

1. Add trampolining configuration constant:
   ```java
   private static final int SYNC_ITERATION_LIMIT = 100;
   ```

2. Add counter array inside the loop closure:
   ```java
   final int[] syncIterationCount = {0};
   ```

3. Reset counter on async completion (in the callback when `state[0] != running`):
   ```java
   syncIterationCount[0] = 0;
   ```

4. Increment counter and check limit on synchronous completion (when `state[0] == syncSuccess`):
   ```java
   syncIterationCount[0]++;
   if (syncIterationCount[0] >= SYNC_ITERATION_LIMIT) {
       // Force async to prevent blocking
       syncIterationCount[0] = 0;
       CompletableFuture.runAsync(() -> {
           try {
               loop[0].run();
           } catch (Throwable t2) {
               callback.completeExceptionally(t2);
           }
       });
       return;
   }
   continue; // Continue synchronously if under limit
   ```

### Optional Enhancement: Make Limit Configurable

Consider making `SYNC_ITERATION_LIMIT` configurable via system property for tuning:
```java
private static final int SYNC_ITERATION_LIMIT = Integer.getInteger(
    "com.mongodb.async.loopWhile.syncIterationLimit",
    100
);
```

## Critical Files

**Primary implementation file:**
- `/Users/maxim.katcharov/code/mongo-java-driver/driver-core/src/main/com/mongodb/internal/async/AsyncRunnable.java` (lines 212-274)
  - Contains `loopWhile()` method with while(true) loop and state machine
  - Only file requiring modification

**Test files to verify:**
- `/Users/maxim.katcharov/code/mongo-java-driver/driver-core/src/test/unit/com/mongodb/internal/async/AsyncFunctionsAbstractTest.java`
  - Contains tests: `testWhile`, `testWhile2`, `testRetryLoop`, `testThenRunRetryingWhile`, `testDoWhileLoop`
  - All should pass unchanged
  - `testRetryLoop` (line 771) tests 101 variations - will now force trampolining once

**Reference files for context:**
- `/Users/maxim.katcharov/code/mongo-java-driver/driver-core/src/test/unit/com/mongodb/internal/async/AsyncFunctionsTestBase.java`
  - Test infrastructure with `InvocationTracker` and `DEPTH_LIMIT = 50`
  - Understanding helps verify test behavior
- `/Users/maxim.katcharov/code/mongo-java-driver/driver-core/src/main/com/mongodb/internal/async/function/AsyncCallbackLoop.java`
  - Old recursive implementation for reference
  - Shows why current optimization was added

## Verification Plan

### 1. Run Existing Tests
Execute the full async test suite to verify all tests pass unchanged:
```bash
./gradlew test --tests '*AsyncFunctions*'
```

Expected: All tests pass, including:
- `testRetryLoop` (101 variations)
- `testThenRunRetryingWhile` (101 variations)
- `testWhile`, `testWhile2` (loop tests)
- `testDoWhileLoop` (67 variations)

### 2. Verify Trampolining Occurs
For `testRetryLoop`, the implementation will now:
- Execute first ~100 iterations synchronously
- Force async scheduling once
- Continue remaining iteration

The test should still pass because it only verifies correctness, not execution model.

### 3. Manual Verification (Optional)
Add temporary logging to confirm trampolining:
```java
if (syncIterationCount[0] >= SYNC_ITERATION_LIMIT) {
    System.out.println("Trampolining after " + syncIterationCount[0] + " iterations");
    // ... force async
}
```

### 4. Check Other Test Suites
Run broader test suite to catch any edge cases:
```bash
./gradlew test
```

### 5. Performance Validation (Optional)
If concerned about overhead, benchmark short loops (< 100 iterations) to verify minimal impact.

## Success Criteria

✅ All existing tests pass without modification
✅ No API changes required in calling code
✅ `loopWhile()` yields thread after 100 consecutive synchronous iterations
✅ Short loops (< 100 iterations) maintain current performance
✅ No new dependencies introduced (uses JDK CompletableFuture)

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| CompletableFuture.runAsync() uses ForkJoinPool.commonPool() | This is standard practice in JDK; acceptable for MongoDB driver |
| Overhead of counter check every iteration | Minimal - single integer increment and comparison |
| 100 iteration limit may be too high/low | Make configurable via system property if needed |
| Async scheduling latency | Only affects long loops that would otherwise block indefinitely |

## Implementation Status

✅ **COMPLETED** - Implementation finished on 2026-02-13

Changes made:
1. Added `SYNC_ITERATION_LIMIT` constant (configurable via system property)
2. Added `syncIterationCount` counter in `loopWhile()` method
3. Reset counter on async completion
4. Added trampolining logic on sync completion after 100 iterations

Ready for testing and verification.
