# Review: PR `nh/backpressure_convenient_api` -> `backpressure`

**PR**: https://github.com/mongodb/mongo-java-driver/pull/1899

## Summary

This PR adds exponential backoff with jitter to the `withTransaction` convenient API per DRIVERS-1934 (JAVA-5950, JAVA-6046, JAVA-6093, JAVA-6113). It also carries forward several unrelated commits merged from `main`.

---

## 1. PR Scope & Unrelated Changes

The branch contains 48 commits. The following are **not part of the backoff feature** and appear to come from main merges:

| Commit | Description |
|--------|-------------|
| `f6cbb327a8` | JAVA-5907 — `submit` -> `execute` rename |
| `0ba1687d21` | Fix RawBsonDocument encoding performance regression (#1888) |
| `e5d8668e1a` | Evergreen atlas search fix (#1894) |
| `c1397fb946` | Update specifications to latest (#1884) |
| `109410230f` | Version bump 5.7.0-SNAPSHOT |
| `7b279402af` | Version bump 5.7.0-beta0 |

Files from these merges that show up in the diffstat but are unrelated to the feature:
- `RawBsonArrayEncodingBenchmark.java`, `RawBsonNestedEncodingBenchmark.java` (perf regression fix)
- `AsynchronousTlsChannel.java`, `AsynchronousTlsChannelGroup.java` (submit->execute rename)
- `BsonDocumentCodec.java`, `DefaultConnectionPool.java` (unrelated fixes)
- Various benchmark files

**Actual feature files** (13 files in the GitHub diff view, ~all feature-relevant):
- `ClientSessionImpl.java` — core implementation
- `ExponentialBackoff.java` — new utility class
- `SystemNanoTime.java` — new time abstraction
- `WithTransactionProseTest.java` — prose tests
- `ExponentialBackoffTest.java` — unit tests
- `ClientSideOperationTimeoutProseTest.java` — CSOT jitter override
- `TimeoutContext.java`, `StartTime.java`, `TimePoint.java`, `Time.java` — supporting changes
- `ClientSessionClock.java` — deleted (replaced by `SystemNanoTime`)

---

## 2. Spec Compliance Issues (Critical)

### 2.1 Spec submodule is outdated
[Mentioned in PR by stIncMale — [discussion_r2954801849](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2954801849)]

The spec submodule is pinned to `bb9dddd8`, but the implementation relies on behaviors defined in two later spec commits:

- **`e8345205` — DRIVERS-3391**: Clarifies that `withTransaction` should throw a timeout error (not re-throw the original error) when backoff would exceed the timeout.
- **`1125200e` — DRIVERS-3370**: Allows jitter range to include 1.0 (i.e., `[0, 1]` instead of `[0, 1)`).

**Action required**: Update the spec submodule to include at least commit `1125200e` before merging.

### 2.2 Error labels not copied to wrapping timeout exception (DRIVERS-3391)
[Mentioned in PR by stIncMale — [discussion_r2931795298](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2931795298), [discussion_r2962554109](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2962554109)]

DRIVERS-3391 requires the wrapping timeout exception to expose the error labels from the cause. However, the constructor chain `MongoTimeoutException(String, Throwable)` → `MongoClientException(String, Throwable)` → `MongoException(String, Throwable)` at `MongoException.java:109` does **NOT** copy labels from the cause. Only `MongoException(int, String, Throwable)` at line 119 does:

```java
// Line 109 — used by MongoTimeoutException — NO label copy:
public MongoException(@Nullable final String msg, @Nullable final Throwable t) {
    super(msg, t);
    code = -4;
}

// Line 119 — copies labels, but not in the inheritance chain of MongoTimeoutException:
public MongoException(final int code, final String msg, final Throwable t) {
    super(msg, t);
    this.code = code;
    if (t instanceof MongoException) {
        addLabels(((MongoException) t).getErrorLabels());  // ← label copy
    }
}
```

This affects **both paths** in `timeoutException()`:
- CSOT: `createMongoTimeoutException(cause)` → `MongoOperationTimeoutException(String, Throwable)` → same chain, no labels
- Legacy: `new MongoTimeoutException("...", cause)` → no labels

**Action required**: Explicitly copy labels from the cause `MongoException` to the wrapping timeout exception, e.g. via `addLabels(cause.getErrorLabels())` after construction.

### 2.3 Jitter supplier Javadoc is inconsistent
[Mentioned in PR by Copilot — [discussion_r2968328501](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2968328501)]

`ExponentialBackoff.java:65` says `[0, 1)` but tests use `1.0` and DRIVERS-3370 allows it. Production code uses `ThreadLocalRandom.nextDouble()` which returns `[0, 1)`. The Javadoc should be updated or the discrepancy documented.

---

## 3. Correctness Issues

### 3.1 ~~`copyTimeoutContext()` removal — is reuse safe?~~ (Resolved)

~~The old code called `copyTimeoutContext()` to create a fresh timeout context for each `startTransaction` call.~~

**After verification**: `TimeoutContext` has all `final` fields, `Timeout` is immutable by contract, and the old `copyTimeoutContext()` returned `new TimeoutContext(getTimeoutSettings(), getTimeout())` — sharing the same objects. The "copy" was semantically a no-op. Reusing the same instance is safe. See section 9.

### 3.2 ExponentialBackoff Javadoc says "0-based" but requires >0

`ExponentialBackoff.java:49` says `@param attemptNumber 0-based attempt number`, but line 53 asserts `attemptNumber > 0`, and the formula uses `attemptNumber - 1`. All callers pass 1-based values. The Javadoc should say **"1-based attempt number"**.

### 3.3 Format string spacing

`WithTransactionProseTest.java:242`:
```java
String.format("Expected withBackoffTime to be ~% dms (...)", ...)
```
`% d` is valid Java (space flag for positive numbers), producing `~ 1234ms`. Likely unintentional — should be `~%dms`.

### 3.4 Redundant `clearTransactionContextOnError` in `withTransaction`
[Mentioned in PR by stIncMale — [discussion_r2925002070](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2925002070)]

`ClientSessionImpl.java:313` calls `clearTransactionContextOnError(e)` after `commitTransaction` throws, but `commitTransaction` itself already calls `clearTransactionContextOnError(e)` at line 230. The call in `withTransaction` is redundant.

### 3.5 `applyMajorityWriteConcernToTransactionOptions` called for whole-transaction retry
[Mentioned in PR by stIncMale — [discussion_r2925016769](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2925016769)]

At line 319, `applyMajorityWriteConcernToTransactionOptions()` is called inside the commit-retry loop, but the `continue outer` at line 328 means it can execute before a whole-transaction retry (not just a commit retry). This could corrupt write concern settings for the next transaction attempt.

### 3.6 ~~Redundant timeout check after transient error in callback~~ (Retracted)
[Mentioned in PR by stIncMale — [discussion_r2924993189](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2924993189)]

~~The timeout check at lines 293-300 is not required by the spec and is redundant.~~

**After verification**: The DRIVERS-3391 pseudocode explicitly includes this check in step 7.2. The implementation is correct. See section 9.

---

## 4. Design Questions (Need Explanation)

### 4.1 ~~Why was `copyTimeoutContext()` removed?~~ (Resolved)

See 3.1 — verified safe after tracing the code. The copy was semantically a no-op.

### 4.2 Non-CSOT timeout wrapping is a behavioral change (Confirmed spec-required)

`ClientSessionImpl.java:408-412`:
```java
private static MongoException timeoutException(final boolean hasTimeoutMS, final Throwable cause) {
    return hasTimeoutMS
            ? createMongoTimeoutException(cause)
            : new MongoTimeoutException("Operation exceeded the timeout limit", cause);
}
```

In the legacy (non-CSOT) case, the old code threw the original error directly when the 120s retry limit expired. The new code wraps it in `MongoTimeoutException`. **After verification**: DRIVERS-3391 Note 1 explicitly requires `makeTimeoutError()` for both paths. The pseudocode has `createLegacyMongoTimeoutException(error)` for non-CSOT. This is an intentional, spec-required behavioral change.

### 4.3 Static mutable `testJitterSupplier`

`ExponentialBackoff.java:41` — static mutable with no synchronization, acknowledged by `TODO-JAVA-6079`. Thread safety concern for parallel tests.

### 4.4 `withTransaction` structure doesn't obviously follow spec
[Mentioned in PR by stIncMale — [discussion_r2925159848](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2925159848)]

stIncMale proposed a comprehensive refactoring (see `stIncMale@fd951e9`) to make the implementation obviously follow the spec's algorithm. The current structure with nested loops and interleaved concerns makes it hard to verify spec compliance.

### 4.5 `timeoutException` should accept `MongoException` not `Throwable`
[Mentioned in PR by stIncMale — [discussion_r2931562540](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2931562540)]

The `cause` parameter is always a `MongoException` at all call sites. Using `Throwable` is unnecessarily broad.

### 4.6 Variable naming: `hasTimeoutMS`
[Mentioned in PR by stIncMale — [discussion_r2915565111](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2915565111)]

Name is ambiguous ("what has the timeoutMS?"). Suggested: `timeoutMsConfigured` or `csotConfigured`.

### 4.7 Dead code: `TimeoutContext` constructor
[Mentioned in PR by stIncMale — [discussion_r2915826686](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2915826686)]

The `TimeoutContext(TimeoutSettings, Timeout)` constructor became unused after `copyTimeoutContext` was removed. Should be deleted.

### 4.8 `timeoutOrAlternative()` method is unnecessary
[Mentioned in PR by stIncMale — [discussion_r2915859064](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2915859064)]

The new `timeoutOrAlternative()` method became unnecessary after adding explicit `hasTimeoutMS` checks. Should be removed.

### 4.9 Span finalization semantics unclear
[Mentioned in PR by stIncMale — [discussion_r2924512938](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2924512938)]

Why is `spanFinalizing` separate from `finalizeTransactionSpan`? What distinguishes `spanFinalizing(true)` from `spanFinalizing(false)`? Why not use the spec term "finish"?

---

## 5. Code Quality Issues

### 5.1 Test class visibility
[Mentioned in PR by stIncMale — [discussion_r2907713051](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2907713051)]

`ExponentialBackoffTest` is `public` but should be package-private (unresolved from prior PR #1852).

### 5.2 Indentation misalignment

`ExponentialBackoffTest.java:38` — `assertTrue` has extra indent, misaligned with surrounding code.

### 5.3 Test error message wording
[Mentioned in PR by stIncMale — [discussion_r2907738273](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2907738273)]

"backoff should be 0-%d ms" → "backoff should be between 0 ms and %d ms".

### 5.4 Magic number in test loop
[Mentioned in PR by stIncMale — [discussion_r2907818612](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2907818612)]

`testCalculateTransactionBackoffMsRespectsMaximum` uses hardcoded `26` — should be `EXPECTED_BACKOFFS_MAX_VALUES.length * 2`.

### 5.5 `measureTransactionLatency` return type
[Mentioned in PR by stIncMale — [discussion_r2908024986](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2908024986)]

Returns `long` millis. Should return `Duration` or rename to `measureTransactionLatencyMs`.

### 5.6 Failpoint document not encapsulated in helper
[Mentioned in PR by stIncMale — [discussion_r2908068291](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2908068291)]

`testRetryBackoffIsEnforced` declares `failPointDocument` outside `measureTransactionLatency` — should be moved into the helper.

### 5.7 Trivial constant comment
[Mentioned in PR by stIncMale — [discussion_r2947759462](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2947759462)]

`ExponentialBackoff.java:32` has comment "Constants for transaction retry backoff" above self-evident constants. Should be removed.

### 5.8 Test assertion patterns
[Mentioned in PR by stIncMale — [discussion_r2947091676](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2947091676), [discussion_r2947239861](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2947239861)]

- `assertEquals(-4, ((MongoException) e).getCode())` is a meaningless assertion (line 179). `-4` is just the default code from `MongoException(String, Throwable)` — it doesn't verify anything useful.
- Use `assertInstanceOf` return value instead of separate casts.
- Use `assertSame` for cause validation instead of complex label re-checking.

### 5.9 Two imports on one line (unrelated commit)

`RawBsonArrayEncodingBenchmark.java:20` — two imports concatenated on one line.

### 5.10 Missing newline at end of file (unrelated commits)

Both `RawBsonArrayEncodingBenchmark.java` and `RawBsonNestedEncodingBenchmark.java` missing trailing newline.

### 5.11 Blank line inside if/else block

`ClientSessionImpl.java:316-318` — blank line between `throw` and `} else {`.

### 5.12 `LOGGER.error(null, t)` — null message (unrelated commit)

`AsynchronousTlsChannelGroup.java:235` and `DefaultConnectionPool.java:1361`. Unusual `null` log message.

### 5.13 CSOT tests globally suppress backoff

`ClientSideOperationTimeoutProseTest.java:46` sets jitter=0 for all CSOT prose tests. No CSOT test exercises actual backoff timing.

---

## 6. Test Coverage Assessment

### Spec prose tests covered

| Spec Test | Implementation |
|-----------|---------------|
| Callback raises custom error | `testCallbackRaisesCustomError()` (line 74) |
| Callback returns value | `testCallbackReturnsValue()` (line 92) |
| Retry timeout enforced (TransientTransactionError) | `testRetryTimeoutEnforcedTransientTransactionError()` (line 108) |
| Retry timeout enforced (UnknownTransactionCommitResult) | `testRetryTimeoutEnforcedUnknownTransactionCommit()` (line 133) |
| Retry timeout enforced (TransientTransactionError on commit) | `testRetryTimeoutEnforcedTransientTransactionErrorOnCommit()` (line 163) |
| Retry backoff is enforced | `testRetryBackoffIsEnforced()` (line 232) |

### Additional tests

- `testExponentialBackoffOnTransientError()` (line 251) — non-spec test verifying transient errors in callback trigger retries.
- `testTimeoutMS()` (line 193) — timeout override prevention.
- `testTimeoutMSAndLegacySettings()` (line 209) — legacy compatibility.

### stIncMale's TODO items
[Comment: [issuecomment-4100546645](https://github.com/mongodb/mongo-java-driver/pull/1899#issuecomment-4100546645)]

- Verify `convenient-transactions.json` spec test ("withTransaction surfaces a timeout after exhausting transient transaction retries") is run.
- Verify prose tests assert all error labels are copied to wrapping exception.

### Coverage gaps

1. **Non-deterministic unit test**: `testCalculateTransactionBackoffMs` uses random jitter and only checks `0 <= backoff <= max`. Could pass with a broken formula.

2. **No `InterruptedException` test**: The `backoff()` method catches `InterruptedException` and converts to `MongoInterruptedException`. No test covers this.

3. **No test for backoff exceeding timeout**: The `shortenBy.onExpired` path (where backoff itself would exceed remaining time) has no dedicated test.

4. **Error labels not asserted on wrapping exception**: The timeout tests (`testRetryTimeoutEnforcedTransientTransactionError` etc.) check labels on `e.getCause()` but do not assert that the wrapping `MongoTimeoutException` itself carries the labels. Given the label-copy bug (section 2.2), these tests would pass even though the spec requirement is violated.

---

## 7. Commit Hygiene

48 commits total, many with vague or repeated messages:

- "PR feedback" (x4)
- "Fixing tests" / "Fixing unit test" (x3)
- "retrigger checks" (x5)
- Multiple commits updating the same file (`WithTransactionProseTest.java` updated 8 times)

**Recommendation**: Squash into a small number of logical commits before merging.

---

## 8. Evaluation of PR Review Comments

### stIncMale's review

stIncMale provided a thorough, multi-round review (21+ comments). The table below evaluates each point, and compares against what my original review (before reading the PR) detected.

Legend for "My original review" column:
- **Detected** — I independently identified the same issue
- **Missed** — I did not identify this; the PR reviewer caught it
- **Related** — I identified a related concern but not this specific issue
- **N/A** — not applicable (e.g., process/TODO items)

| # | Topic | URL | Assessment | My original review |
|---|-------|-----|------------|-------------------|
| 1 | Test class should be package-private | [r2907713051](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2907713051) | **Agree** — standard Java test convention | **Missed** — I did not check access modifiers on test classes |
| 2 | Error message wording | [r2907738273](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2907738273) | **Agree** — clearer phrasing | **Missed** — I flagged the indentation on the same line (5.2) but not the message text |
| 3 | Magic number 26 → data-driven | [r2907818612](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2907818612) | **Agree** — `EXPECTED_BACKOFFS_MAX_VALUES.length * 2` is self-documenting | **Missed** |
| 4 | Return `Duration` from `measureTransactionLatency` | [r2908024986](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2908024986) | **Agree** — but low priority given it's test-only code | **Missed** |
| 5 | Move failpoint doc into helper | [r2908068291](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2908068291) | **Agree** — reduces duplication and coupling | **Missed** |
| 6 | TimeoutContext invariant unclear | [r2915519465](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2915519465) | **Agree** — addressed via separate PR #1908 | **Related** — my 3.1/4.1 raised the `copyTimeoutContext` removal as a safety question, which touches on the same `TimeoutContext` invariant, but I didn't identify the specific `getTimeout()`-null-iff-`getTimeoutMS()`-null invariant |
| 7 | Rename `hasTimeoutMS` | [r2915565111](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2915565111) | **Agree** — `timeoutMsConfigured` is clearer | **Missed** |
| 8 | Dead `TimeoutContext` constructor | [r2915826686](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2915826686) | **Agree** — dead code should be removed | **Missed** — I noted `copyTimeoutContext` was removed but didn't trace the consequence to the now-unused constructor |
| 9 | Remove `timeoutOrAlternative()` | [r2915859064](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2915859064) | **Agree** — unnecessary indirection | **Missed** |
| 10 | Span finalization semantics unclear | [r2924512938](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2924512938) | **Agree** — naming/semantics need documentation or simplification | **Missed** — I did not review the span/tracing logic at all |
| 11 | Redundant timeout check after callback error | [r2924993189](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2924993189) | **Disagree after verification** — the DRIVERS-3391 pseudocode *does* have this check in step 7.2. The implementation matches the spec. See section 9 verification. | **Missed** originally, then initially agreed with stIncMale, then **corrected** after reading the DRIVERS-3391 spec |
| 12 | Redundant `clearTransactionContextOnError` | [r2925002070](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2925002070) | **Agree, but pre-existing** — verified `commitTransaction` calls it at line 230. However, the old code had the same redundancy at old line 287. Not a regression. | **Missed** — I did not trace into `commitTransaction` to check for redundancy |
| 13 | `applyMajorityWriteConcern` scope | [r2925016769](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2925016769) | **Agree, but pre-existing** — the old code has the identical structure (old line 290 before `continue outer` at old line 299). The spec says "We will rely on ClientSession.commitTransaction() to apply a majority write concern" — meaning it should be handled inside `commitTransaction`, not in `withTransaction`. Still worth fixing in the refactoring. | **Missed** — I did not trace `continue outer` control flow through the write concern call |
| 14 | Refactor to match spec structure | [r2925159848](https://github.com/mongodb/mongo-java-driver/pull/1899/files/e5ae458e2807244ee22f59ec3c96e01aef7e00b4#discussion_r2925159848) | **Agree** — proposed `fd951e9` is significantly clearer. The current nested-loop structure with `continue outer` makes spec compliance hard to verify | **Missed** — I flagged cosmetic issues (blank lines, indentation) but did not identify the structural mismatch with the spec algorithm |
| 15 | `timeoutException` param should be `MongoException` | [r2931562540](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2931562540) | **Agree** — all call sites pass `MongoException` | **Missed** |
| 16 | **Error labels not copied** | [r2931795298](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2931795298), [r2962554109](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2962554109) | **Critical, agree** — verified the full constructor chain; neither `MongoTimeoutException` nor `MongoOperationTimeoutException` copy labels. See section 2.2 | **Missed** — this is the most significant issue I failed to catch. I noted the non-CSOT wrapping as a behavioral change (original 4.2) but did not trace the constructor chain to discover labels are lost. stIncMale's deep knowledge of the `MongoException` constructor variants was essential here |
| 17 | Test assertion: `-4` code is meaningless | [r2947091676](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2947091676) | **Agree** — `-4` is just the default from the `MongoException(String, Throwable)` constructor; asserting it verifies nothing useful | **Missed** — I read the test but did not question the `-4` assertion |
| 18 | Use `assertSame` for cause | [r2947239861](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2947239861) | **Agree** — simpler and more precise | **Missed** |
| 19 | Remove trivial constant comment | [r2947759462](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2947759462) | **Agree** — constants are self-evident | **Missed** |
| 20 | Update spec submodule | [r2954801849](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2954801849) | **Critical, agree** — see section 2.1 | **Detected** — my original section 2.1 independently identified this, including the specific commit hashes `e8345205` (DRIVERS-3391) and `1125200e` (DRIVERS-3370) |
| 21 | TODO: verify spec JSON test + label assertions | [issuecomment-4100546645](https://github.com/mongodb/mongo-java-driver/pull/1899#issuecomment-4100546645) | **Important** — must verify before merge | **N/A** — process item, not a code finding |

### Copilot's review

| # | Topic | URL | Assessment | My original review |
|---|-------|-----|------------|-------------------|
| 1 | Jitter Javadoc `[0,1)` vs tests using `1.0` | [r2968328501](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2968328501) | **Agree** — duplicates section 2.3. Copilot's suggestion to "validate/clamp" is overkill; just fix the Javadoc | **Detected** — my original section 2.2 identified this independently |
| 2 | Re-check timeout after sleep | [r2968328513](https://github.com/mongodb/mongo-java-driver/pull/1899/files/9dcd5c04906a96bc0230fa1e8f3bd3585958aa8f#discussion_r2968328513) | **Disagree** — the `shortenBy().onExpired()` check before sleep already accounts for the backoff duration. A post-sleep overrun is bounded by OS scheduling jitter (microseconds). Adding another check adds complexity for negligible safety | **Missed** — but I agree with my own assessment that this is not a real issue, so missing it was correct |

### My original findings: not raised by any PR reviewer

| # | Topic | Section | Status | Notes |
|---|-------|---------|--------|-------|
| A | `copyTimeoutContext()` removal — is reuse safe? | 3.1, 4.1 | **Resolved after verification** — not a problem | After tracing the code: `TimeoutContext` has all `final` fields, `Timeout` is immutable by contract, and the old `copyTimeoutContext()` shared the same objects anyway. See section 9 verification. |
| B | Javadoc says "0-based" but assertion requires >0 | 3.2 | **Still valid** | Clear documentation bug. All callers pass 1-based values. No reviewer mentioned it. |
| C | Format string `"~% dms"` spacing | 3.3 | **Soften** — likely cosmetic, not a bug | `% d` is valid Java (space flag). Produces `~ 1234ms` which reads as "approximately 1234ms." Probably unintentional formatting, but the output is arguably fine. Lower priority than originally stated. |
| D | Non-CSOT timeout wrapping is a behavioral change | 4.2 | **Confirmed correct per spec** after verification | DRIVERS-3391 Note 1 explicitly requires `makeTimeoutError(error)` for both CSOT and non-CSOT paths. The wrapping in `MongoTimeoutException` is intentional. This is a behavioral change from old code, but it's spec-required. See section 9 verification. |
| E | Static mutable `testJitterSupplier` thread safety | 4.3 | **Still valid** — acknowledged by `TODO-JAVA-6079` | No reviewer discussed it. Low risk in practice since tests likely run sequentially, but the pattern is fragile. |
| F | CSOT tests globally suppress backoff | 5.13 | **Still valid** | `ClientSideOperationTimeoutProseTest` sets jitter=0 for all tests. No CSOT test exercises real backoff timing. No reviewer mentioned this. |
| G | Indentation misalignment in `ExponentialBackoffTest.java:38` | 5.2 | **Still valid** | Minor formatting issue. No reviewer mentioned it. |
| H | Blank line in if/else block at `ClientSessionImpl.java:317` | 5.11 | **Soften** — would be resolved by stIncMale's refactoring | If `fd951e9` is adopted, this code is restructured entirely. Only relevant if the current structure is kept. |
| I | Non-deterministic unit test | 6 gap #1 | **Still valid** | `testCalculateTransactionBackoffMs` uses random jitter and asserts only broad bounds. Could pass with a broken formula. No reviewer mentioned this. |
| J | No `InterruptedException` test | 6 gap #2 | **Still valid** but low priority | Verified that `interruptAndCreateMongoInterruptedException` correctly restores the interrupt flag (`InterruptionUtil.java:40`), so the code path is correct — just untested. |
| K | No test for backoff-exceeds-timeout path | 6 gap #3 | **Still valid** | The `shortenBy.onExpired` path has no dedicated test. Partially covered by `testRetryBackoffIsEnforced` but not directly asserted. |
| L | Test coverage: labels not asserted on wrapping exception | 6 gap #4 | **Still valid** — reinforces stIncMale #16 | I identified this gap *after* reading the PR comments about the label-copy bug. Credit goes to stIncMale for the root cause; this test gap is a consequence. |

### My original findings: retracted or corrected

| # | Topic | Original section | Retraction reason |
|---|-------|-----------------|-------------------|
| R1 | "30 files in diff, ~15 are feature-relevant" | 1 | **Retracted** — the GitHub PR diff shows **13 files**, all feature-relevant. My local `git diff backpressure...` included files from unrelated main-merge commits (benchmarks, `AsynchronousTlsChannel`, `BsonDocumentCodec`, `DefaultConnectionPool`) that are NOT visible in the GitHub PR view. Reviewers never see these files. |
| R2 | Two imports on one line (`RawBsonArrayEncodingBenchmark.java:20`) | 5.9 | **Retracted** — file is not in the GitHub PR diff. This is from an unrelated commit only visible in local three-dot diff. |
| R3 | Missing newlines in benchmark files | 5.10 | **Retracted** — same as R2; files not in the GitHub PR diff. |
| R4 | `LOGGER.error(null, t)` in `AsynchronousTlsChannelGroup.java` and `DefaultConnectionPool.java` | 5.12 | **Retracted** — neither file is in the GitHub PR diff. These are from the unrelated `submit`→`execute` commit. |
| R5 | Spec submodule listed as a "file change" | 1 | **Corrected** — the submodule diff (`testing/resources/specifications`) does not appear in the GitHub PR files view, even though `git diff` shows it locally. stIncMale still correctly flagged the submodule version as an issue, but it's not visible as a file change in the PR. |

### Self-assessment summary

### Review phases

This review was conducted in three phases, each building on the previous:

1. **Phase 1 — Independent review** (sections 1–7): Read the code and wrote findings without consulting the PR. Identified spec submodule issue, Javadoc inconsistencies, `copyTimeoutContext` reuse question, formatting issues, test coverage gaps. Missed all deep behavioral issues.

2. **Phase 2 — PR comment evaluation** (section 8): Read all 23 reviewer comments and evaluated each. Initially agreed with all of stIncMale's findings. Added PR-comment-aware annotations throughout the document. Identified 5 items from my original review that needed retraction (all from using local `git diff` instead of GitHub PR view).

3. **Phase 3 — Verification against codebase and spec** (section 9): Traced actual code paths, read old implementation at merge base, and read the spec at both `bb9dddd8` and DRIVERS-3391 (`e8345205`). This changed several conclusions:
   - **Resolved** finding A (`copyTimeoutContext` reuse) — `TimeoutContext` is effectively immutable, copy was a no-op
   - **Confirmed** finding D (non-CSOT wrapping) as spec-required, not just a behavioral change
   - **Disagreed** with stIncMale #11 — the timeout check after callback error IS in the DRIVERS-3391 spec
   - **Nuanced** stIncMale #12 and #13 — both correct findings, but both pre-existing in the old code

**Against PR reviewer comments** (23 total):
- **Detected independently**: 2 (spec submodule outdated, jitter Javadoc inconsistency)
- **Related but less specific**: 1 (TimeoutContext invariant)
- **Missed entirely**: 18
- **Disagreed after verification**: 1 (stIncMale #11 — timeout check is spec-required)
- **N/A**: 1 (process/TODO item)

**My unique findings**: 12 items not raised by any reviewer (A–L), of which 1 was resolved by verification (A), 1 confirmed as spec-required (D), 2 softened (C, H), 7 remain valid (B, E, F, G, I, J, K), 1 derived from a reviewer's finding (L).

**Retracted**: 5 items (R1–R5), all stemming from the same root cause — local `git diff` included files not in the GitHub PR view.

**Biggest gap in my original review**: I failed to catch the label-copy bug (stIncMale #16), which is the most critical issue in the PR. I noted the timeout wrapping as a behavioral change (D) but did not trace the `MongoException` constructor chain to discover labels are silently dropped. This required deep familiarity with the `MongoException` class hierarchy.

**Strongest unique contribution**: After verification, the "0-based" vs "1-based" Javadoc bug (B) and the non-deterministic unit test concern (I) are the most substantive unique findings that remain valid and unaddressed.

**Correction of a reviewer**: stIncMale's #11 (redundant callback timeout check) was accepted by the PR author but is actually spec-required per DRIVERS-3391. If the refactoring at `fd951e9` removes this check, it would deviate from the spec. This is the one case where the verification pass contradicted a reviewer finding.

---

## 9. Verification Pass: Findings Checked Against the Codebase

After the initial independent review (sections 1–7) and the evaluation of PR comments (section 8), a third pass was done to verify key findings by tracing the actual code, reading the old implementation, and reading the spec at both the submodule commit (`bb9dddd8`) and the DRIVERS-3391 commit (`e8345205`).

### Verified: `copyTimeoutContext()` removal is safe (finding A — downgraded)

The old code called `copyTimeoutContext()` which did:
```java
return new TimeoutContext(getTimeoutSettings(), getTimeout());
```
This creates a new `TimeoutContext` wrapper but passes the **same `Timeout` and `TimeoutSettings` objects**. Since `TimeoutContext` has all `final` fields (`TimeoutContext.java:43-49`) and `Timeout` is immutable by contract (`Timeout.java:43`: "Implementations of this interface must be immutable"), the "copy" provided no isolation — both the old and new `TimeoutContext` shared the same underlying `Timeout` deadline. The new code reusing `withTransactionTimeoutContext` directly is therefore **semantically equivalent** to the old code. Finding A is **no longer a concern**.

However, stIncMale's related finding (#8) that the `TimeoutContext(TimeoutSettings, Timeout)` constructor is now dead code remains valid — it was only used by the now-removed `copyTimeoutContext()`.

### Verified: `applyMajorityWriteConcern` scope bug is pre-existing (stIncMale #13 — nuanced)

The old code has the **identical structure** — `applyMajorityWriteConcernToTransactionOptions()` is called at old line 290 before `continue outer` at old line 299. So this is a **pre-existing issue**, not a regression. stIncMale's finding is correct that it's a bug, but it's not introduced by this PR. However, since the PR is restructuring `withTransaction`, it's a good opportunity to fix it — and stIncMale's refactoring at `fd951e9` likely does.

### Verified: redundant `clearTransactionContextOnError` is pre-existing (stIncMale #12 — nuanced)

The old code also calls `clearTransactionContextOnError(e)` at old line 287 inside `withTransaction`, in addition to the call inside `commitTransaction` at old line 222. Same pattern, same redundancy. Again, not a regression.

### Re-evaluated: timeout check after callback error is NOT redundant (stIncMale #11 — disagree)

After reading the DRIVERS-3391 spec pseudocode, the callback error path **does** contain a timeout check:
```typescript
if (error.hasErrorLabel("TransientTransactionError")) {
    if (Date.now() - startTime < timeout) {
        continue retryTransaction;
    } else {
        throw makeTimeoutError(error)
    }
}
```
The implementation at `ClientSessionImpl.java:292-300` mirrors this exactly. stIncMale's assertion that this check is "not needed because we check at the beginning of the next attempt" is **incorrect per the DRIVERS-3391 spec**. The spec has both checks: one here (to avoid an unnecessary loop iteration when already timed out) and one in `backoff()` (to avoid sleeping past the timeout). They serve different purposes — the callback check avoids re-entering the loop at all, while `backoff()` checks `elapsed + backoffMs >= timeout` which is a tighter bound. If stIncMale's refactoring at `fd951e9` removes this check, it would deviate from the spec.

### Verified: non-CSOT timeout wrapping is spec-required (finding D — confirmed)

DRIVERS-3391 Note 1 says:
> "If `timeoutMS` is not set, then propagate it as timeout error if the language allows to expose the underlying error as a cause of a timeout error"

And the pseudocode uses `makeTimeoutError(error)` for both CSOT and non-CSOT paths:
```typescript
function makeTimeoutError(error) {
    return getCSOTTimeoutIfSet() != null ? createCSOTMongoTimeoutException(error) : createLegacyMongoTimeoutException(error);
}
```

So wrapping in `MongoTimeoutException` for the non-CSOT case is **spec-required by DRIVERS-3391**. This is indeed a behavioral change from the old code (which threw the original error directly), but it's intentional. Finding D is confirmed as a behavioral change, but it's correct per spec.

### Verified: error labels SHOULD be exposed (stIncMale #16 — confirmed critical)

DRIVERS-3391 Note 1 explicitly says:
> "If timeout error is thrown then it SHOULD expose error label(s) from the transient error."

The implementation does NOT do this — the `MongoTimeoutException` constructor chain never copies labels (verified: `MongoException(String, Throwable)` at `MongoException.java:109` has no label copy, unlike `MongoException(int, String, Throwable)` at line 119). This is a **confirmed spec violation**.

### Verified: no backoff on commit retries is spec-correct (section 9.3 — resolved)

The spec pseudocode has backoff only in the `retryTransaction` loop (step 2), not in the `retryCommit` loop. The implementation matches — `backoff()` is only called in the outer loop. My section 9.3 concern is **not a problem**.

### Verified: DRIVERS-3391 also adds timeout checks in the commit retry loop

The DRIVERS-3391 pseudocode adds `if (Date.now() - startTime >= timeout) { throw makeTimeoutError(error); }` at the **top** of the commit error handler, before the label checks. The implementation has this at `ClientSessionImpl.java:315` via `withTransactionTimeoutExpired.getAsBoolean()`. This matches. However, the old (pre-DRIVERS-3391) spec only checked `Date.now() - startTime < timeout` as a **condition** on the `UnknownTransactionCommitResult` retry — it didn't have a standalone timeout-exceeded check that throws `makeTimeoutError`. So the implementation correctly reflects DRIVERS-3391, but the submodule doesn't include that spec version (section 2.1).

---

## 10. Additional Suggestions Beyond Existing Review Comments

### 10.1 The label-copy bug likely affects other `createMongoTimeoutException` callers

stIncMale identified the label-copy bug in the `withTransaction` context, but `TimeoutContext.createMongoTimeoutException(Throwable)` at `TimeoutContext.java:66-68` is used in **many other places** (GridFS, connection pool, etc.). If any of those callers wrap a `MongoException` that carries error labels, the same bug applies. A grep shows ~20 call sites. Worth auditing whether this is a broader issue or only matters for `withTransaction`.

### 10.2 `testRetryBackoffIsEnforced` tolerance may be fragile

The test at `WithTransactionProseTest.java:242` uses a 500ms tolerance window. The expected backoff sum for 13 retries with jitter=1.0 is ~1800ms. However, the test measures wall-clock time which includes:
- Network round trips (13 commit attempts + 1 success)
- Failpoint processing overhead
- GC pauses

The `noBackoffTime` baseline accounts for network overhead, but the subtraction assumes server processing time is consistent between the two runs. On a loaded CI machine, 500ms tolerance could be tight. The spec likely defines a tolerance — worth checking it matches.

### 10.3 ~~`backoff()` is only called for the outer transaction retry, not for commit retries~~ (Resolved)

~~The spec may or may not require backoff on commit retries.~~

**After verification**: The spec pseudocode has backoff only in the `retryTransaction` loop (step 2), not in the `retryCommit` loop. The implementation matches. Not a problem.

### 10.4 ~~`interruptAndCreateMongoInterruptedException` — verify thread interrupt flag is restored~~ (Verified OK)

**After verification**: `InterruptionUtil.java:40` calls `Thread.currentThread().interrupt()` before creating the exception. The interrupt flag is correctly restored. Not a problem.

---

## Summary of Action Items

| Priority | Item | Section | Status in PR | Effort |
|----------|------|---------|-------------|--------|
| **Critical** | Copy error labels to wrapping timeout exception | 2.2 | Identified by stIncMale, unresolved | **Low** — add `addLabels(cause.getErrorLabels())` after constructing the timeout exception in `timeoutException()`, or override the constructor. ~5 lines. But needs care: must decide whether to copy labels in `MongoTimeoutException` constructors globally or just at the `withTransaction` call site. If done globally, audit other callers. |
| **Critical** | Update spec submodule to ≥ `1125200e` | 2.1 | Identified by stIncMale, unresolved | **Trivial** — `git submodule update` to the right commit, verify tests still pass. Mechanical, but may pull in other spec changes that need review. |
| **High** | Adopt stIncMale's refactoring (`fd951e9`) or equivalent | 4.4 | Proposed, not yet applied | **Medium** — `fd951e9` already exists and is a working diff (+57/−52 lines). Requires careful review against DRIVERS-3391 spec (note: must preserve the callback timeout check that `fd951e9` may remove — see section 9). Test re-run needed. |
| **High** | Fix `applyMajorityWriteConcern` scope bug (pre-existing) | 3.5 | Identified by stIncMale; verified pre-existing | **Low** if done as part of the refactoring — move the call after the label check so it only runs for `UnknownTransactionCommitResult` commit retries, not `TransientTransactionError` whole-transaction retries. ~3-line reorder. Subsumed by `fd951e9`. |
| **High** | Add test assertions for labels on wrapping exception | 6 gap #4 | Implied by stIncMale's TODO | **Low** — add `assertTrue(e.hasErrorLabel(...))` to the existing timeout prose tests. ~5 lines across 3 tests. Depends on the label-copy fix landing first. |
| **Medium** | Remove dead `TimeoutContext` constructor | 4.7 | Identified by stIncMale | **Trivial** — delete 3 lines (`TimeoutContext.java:112-114`). |
| **Medium** | Remove `timeoutOrAlternative()` | 4.8 | Identified by stIncMale | **Low** — delete method (~3 lines), replace 1 call site with inline conditional. |
| **Medium** | Remove redundant `clearTransactionContextOnError` (pre-existing) | 3.4 | Identified by stIncMale; verified pre-existing | **Trivial** — delete 1 line. Subsumed by `fd951e9`. |
| ~~Medium~~ | ~~Remove redundant timeout check after callback error~~ | ~~3.6~~ | ~~Identified by stIncMale~~ — **retracted**: check is spec-required per DRIVERS-3391 | N/A |
| **Medium** | Fix Javadoc: "0-based" → "1-based" | 3.2 | Not discussed in PR | **Trivial** — change one word in a comment. |
| **Medium** | Fix jitter Javadoc `[0,1)` → `[0,1]` | 2.3 | Copilot + this review | **Trivial** — change two characters in a comment. |
| **Medium** | Rename `hasTimeoutMS` | 4.6 | Identified by stIncMale | **Low** — rename variable + parameter in 2 methods. Subsumed by `fd951e9`. |
| **Low** | Test class visibility, error messages, magic numbers, assertion patterns | 5.x | Various stIncMale comments | **Low** — each is a 1–3 line change. ~10 small edits total across `ExponentialBackoffTest` and `WithTransactionProseTest`. |
| **Low** | Squash commits | 7 | Not discussed in PR | **Low** — interactive rebase. Mechanical but time-consuming to pick good commit boundaries. ~30 min. |
