/*
 * Copyright 2008-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mongodb.reactivestreams.client;

import com.mongodb.Function;
import com.mongodb.internal.async.SingleResultCallback;
import com.mongodb.lang.Nullable;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

import static com.mongodb.ClusterFixture.getAsyncBinding;
import static com.mongodb.ClusterFixture.getBinding;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestTest {


    @Test
    public void test() {
        System.out.println("--------");
        try {
            sendAndReceive("message");
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        System.out.println("--------");
        sendAndReceiveAsync1("message", (r, e) -> {
            if (e != null) {
                System.out.println(e.getMessage());
            }
        });
//        System.out.println("--------");
//        sendAndReceiveAsync2("message", (r, e) -> {
//            if (e != null) {
//                System.out.println(e.getMessage());
//            }
//        });
//        System.out.println("--------");
//        sendAndReceiveAsync3("message", (r, e) -> {
//            if (e != null) {
//                System.out.println(e.getMessage());
//            }
//        });
//        System.out.println("--------");
//        sendAndReceiveAsync4("message", (r, e) -> {
//            if (e != null) {
//                System.out.println(e.getMessage());
//            }
//        });
        System.out.println("--------");
        sendAndReceiveAsync5("message", (r, e) -> {
            if (e != null) {
                System.out.println(e.getMessage());
            }
        });
        System.out.println("--------");

        if (true) {
            return;
        }

//
//        SingleResultCallback<String> returner = (a,b) -> {
//            System.out.println("END:" + a);
//        };
//
//        printAsync("a",
//                (r, t) -> printAsync(2 + r,
//                        (r2, t2) -> printAsync("c" + r2,
//                                returner)));
//
//
//        System.out.println("-----");
//
//        SingleResultCallback<Integer> cc = (r, t) -> printAsync("c", returner);
//        SingleResultCallback<String> bb = (r, t) -> printAsync(2, cc);
//        SingleResultCallback<String> aa = (r, t) -> printAsync("a", bb);
//        aa.onSuccess(null);
//
//        System.out.println("-----");


//        async()
//                .nowDo((SingleResultCallback<Integer> c) -> printAsyncA(c))
//                .nowDo((SingleResultCallback<Boolean> c) -> printAsyncB(c))
//                .nowDo((SingleResultCallback<String> c) -> printAsyncC(c))
//                //.end(returner);
//                ;

//        async()
//                .thenDo(printAsync2("a"))
//                .thenDo(printAsync2("b"))
//                .thenDo(printAsync2("c"))
//                .thenDo(wrap(returner));



//        printAsync("a",
//                (r, t) -> printAsync(2 + r,
//                        (r2, t2) -> printAsync("c" + r2,
//                                returner)));

        System.out.println("-----");
        System.out.println("-----");

        String s = syncStr(true);
        Integer i = syncSize(s);
        Boolean b = syncEven(i);
        System.out.println("RESULT1:" + b);

        System.out.println("-----");

        asyncStr(true,
                (ss,e1) -> asyncSize(ss,
                        (ii, e2) -> asyncEven(ii,
                                (bbb, e3) -> System.out.println("RESULT2:" + bbb))));

        System.out.println("-----");

        SingleResultCallback<Boolean> x3 = (bbb, e3) -> System.out.println("RESULT3:" + bbb);
        SingleResultCallback<Integer> x2 = (ii, e2) -> asyncEven(ii, x3);
        SingleResultCallback<String> x1 = (ss, e1) -> asyncSize(ss, x2);
        asyncStr(true, x1);

        System.out.println("-----");
        {
            AsyncFunction<Boolean, String> xx0 = (v, c) -> asyncStr(v, c);
            AsyncFunction<String, Integer> xx1 = (v, c) -> asyncSize(v, c);
            AsyncFunction<Integer, Boolean> xx2 = (v, c) -> asyncEven(v, c);
            AsyncFunction<Boolean, Void> xx3 = (v, c) -> System.out.println("RESULT4:" + v);
            //AsyncFunction<Boolean, Integer> xx01 = dot(xx0, xx1);
            TestTest.<Boolean>startAsync()
                    .dot(xx0)
                    .dot(xx1)
                    .dot(xx2)
                    .dot(xx3)
                    .applyAsync(true, (rr, ee) -> {});
        }
        System.out.println("-----");
        {
            //AsyncFunction<Boolean, Integer> xx01 = dot(xx0, xx1);
            TestTest.<Boolean>startAsync()
                    .<String>dot(asyncStrW())
                    .<Integer>dot((v1, c1) -> asyncSize(v1, c1))
                    .<Boolean>dot((v2, c2) -> asyncEven(v2, c2))
                    .<Void>dot((v3, c3) -> System.out.println("RESULT5:" + v3))
                    .applyAsync(true, (rr, ee) -> {});
        }


    }


    @NotNull
    private static <T> AsyncFunction<T, T> startAsync() {
        return (v, c) -> c.onResult(v, null);
    }

    @NotNull
    private static AsyncCallable asyncCall() {
        return (c) -> c.onResult(null, null);
    }

    @NotNull
    private static AsyncFunction<Void, Void> startAsyncVoid() {
        return TestTest.startAsync();
    }


    @NotNull
    private <T1, T2, T3> AsyncFunction<T1, T3> dot(final AsyncFunction<T1, T2> xx0, final AsyncFunction<T2, T3> xx1) {
        return (bbb, c) -> {
            xx0.applyAsync(bbb, (r, e) -> {
                if (e != null) {
                    c.onResult(null, e);
                } else {
                    xx1.applyAsync(r, c);
                }
            });
        };
    }

    public interface AsyncBiFunction<P1, P2, R1> {
        void applyAsync(@Nullable P1 p1, @Nullable P2 p2, SingleResultCallback<R1> continuation);
    }

    public interface AsyncCallable {
        void invoke(SingleResultCallback<Void> continuation); // VoidResultCallback

        default AsyncCallable then(final AsyncCallable callable) {
            return (c) -> {
                this.invoke((r, e) -> {
                    if (e != null) {
                        c.onResult(null, e);
                    } else {
                        callable.invoke(c);
                    }
                });
            };
        }


        default AsyncCallable onErrorIf(
                final Function<Throwable, Boolean> errorCheck,
                final AsyncCallable callable) {
            return (callback) -> this.invoke((r, e) -> {
                if (e != null && errorCheck.apply(e)) {
                    callable.invoke(callback);
                } else {
                    callback.onResult(r, null);
                }
            });
        }
    }


    public interface AsyncFunction<T, T2> {
        void applyAsync(@Nullable T input, SingleResultCallback<T2> continuation);

        default <T3> AsyncFunction<T, T3> dot(final AsyncFunction<T2, T3> xx1) {
            return (bbb, c) -> {
                this.applyAsync(bbb, (r, e) -> {
                    if (e != null) {
                        c.onResult(null, e);
                    } else {
                        xx1.applyAsync(r, c);
                    }
                });
            };
        }

        default AsyncFunction<T, T2> onError(final AsyncBiFunction<T2, Throwable, T2> xx1) {
            return (bbb, c) -> {
                this.applyAsync(bbb, (r, e) -> {
                    if (e != null) {
                        xx1.applyAsync(r, e, c);
                    } else {
                        c.onResult(r, null);
                    }
                });
            };
        }

        default AsyncFunction<T, T2> onErrorIf(
                final Function<Throwable, Boolean> errorCheck,
                final AsyncFunction<T2, T2> xx1) {
            return (input, callback) -> {
                this.applyAsync(input, (r, e) -> {
                    if (e != null && errorCheck.apply(e)) {
                        xx1.applyAsync(r, callback);
                    } else {
                        callback.onResult(r, null);
                    }
                });
            };
        }

//        default T2 callback(final T input, final SingleResultCallback<String> returner) {
//            this.applyAsync();
//            AsyncFunction<Boolean, String> xx0 = (bbb, c) -> asyncStr(bbb, c);
//        }
    }

    private Boolean syncEven(final Integer i) {
        return i % 2 == 0;
    }

    private void asyncEven(@Nullable final Integer i, final SingleResultCallback<Boolean> callback) {
        callback.onResult(i % 2 == 0, null);
    }


    private Integer syncSize(final String s) {
        return s.length();
    }

    private void asyncSize(@Nullable final String s, final SingleResultCallback<Integer> callback) {
        callback.onResult(s.length(), null);
    }

    private String syncStr(final boolean b) {
        return "" + b;
    }

    private void asyncStr(@Nullable final Boolean b, final SingleResultCallback<String> callback) {
        callback.onResult("" + b, null);
    }

    @NotNull
    private AsyncFunction<Boolean, String> asyncStrW() {
        return (v, c) -> c.onResult("" + v, null);
    }


    private <T> Thing<T> printAsync2(final T message) {
        System.out.println("message: " + message);
        return null;// callback.onSuccess(message);
    }


    private <T> void printAsync(final T message, final SingleResultCallback<T> callback) {
        System.out.println("message: " + message);
        callback.onResult(message, null);
    }
    private void printAsyncA(final SingleResultCallback<Integer> callback) {
        System.out.println("message: a");
        callback.onResult(1, null);
    }
    private void printAsyncB(final SingleResultCallback<Boolean> callback) {
        System.out.println("message: b");
        callback.onResult(true, null);
    }
    private void printAsyncC(final SingleResultCallback<String> callback) {
        System.out.println("message: c");
        callback.onResult("abc", null);
    }





    private <T> void sendAndReceiveAsync2(final String message, final SingleResultCallback<T> callback) {
        sendAndReceiveInternalAsync(message,
                onErrorIf(
                        (e) -> triggers(e),
                        (r, e) -> reauthAsync(onSuccess(
                                (r2, e2) -> sendAndReceiveInternalAsync(message, callback),
                                callback)),
                        callback)
        );
    }

    private void sendAndReceive(final String message) {
        try {
            sendAndReceiveInternal(message);
        } catch (Exception e) {
            if (triggers(e)) {
                reauth();
                sendAndReceiveInternal(message);
            }
            throw e;
        }
    }


    private <T> void sendAndReceiveAsync5(final String message, final SingleResultCallback<Void> returner) {
        asyncCall()
                .then(c -> sendAndReceiveInternalAsync(message, c))
                .onErrorIf((e) -> triggers(e), asyncCall()
                        .then(c -> reauthAsync(c))
                        .then(c -> sendAndReceiveInternalAsync(message, c)))
                .invoke(returner);
    }


    private <T> void sendAndReceiveAsync4(final String message, final SingleResultCallback<Void> returner) {
        sendAndReceiveInternalAsync2(message)
                .onErrorIf(
                        (e) -> triggers(e),
                        reauthAsync2()
                                .dot(sendAndReceiveInternalAsync2(message)))
                .applyAsync(null, returner);
    }




    private <T> void sendAndReceiveAsync3(final String message, final SingleResultCallback<T> returner) {

//        async()
//                .nowDo(c -> sendAndReceiveInternalAsync(message, c))
//
//
//                .catchError(er -> async()
//                        .ifElse(() -> triggers(er), async()
//                                .nowDo(c -> reauthAsync(c))
//                                .nowDo(c -> sendAndReceiveInternalAsync(message, c))
//                        )
//                        .nowDo(c -> c.onError(er))
//                )
//                .nowDo(returner);


        sendAndReceiveInternalAsync(message,
                onErrorIf(
                        (e) -> triggers(e),
                        (r, e) -> reauthAsync( onSuccess(
                                (r2, e2) -> sendAndReceiveInternalAsync(message, returner),
                                returner)
                        ), returner)
        );
    }



    private static <T> Thing wrap(final Consumer<SingleResultCallback<T>> a) {
        return null;
    }
    static class Thing<T> {

//        private final SingleResultCallback<T> returner;

        private final List<SingleResultCallback<T>> callbacks = new ArrayList<>();

        public Thing(final SingleResultCallback<T> returner) {
//            this.returner = returner;
        }
        public Thing() {
        }


        public void end(final SingleResultCallback<T> returner) {
        }

        public <Q> Thing<T> nowDo(final Consumer<SingleResultCallback<Q>> a) {
            return null;
        }
        public Thing<T> thenDo(final Thing<T> a) {
            return null;
        }

        public Thing<T> ifElse(final Object o, final T nowDo) {
            return null;
        }

        public Thing<T> catchError(final Function<Throwable, Thing<T>> o) {
            return null;
        }
    }

    private <T> Thing<T> wrap2(final SingleResultCallback<T> returner) {
        return new Thing<T>(returner);
    }

    private <T> Thing<T> async() {
        return new Thing<T>(null);
    }


    private <T> SingleResultCallback<T> onSuccess(
            final SingleResultCallback<T> callback1,
            final SingleResultCallback<T> callback2) {
        return (T r, Throwable e) -> {
            if (e == null) {
                callback1.onResult(r, e);
            } else {
                callback2.onResult(r, e);
            }
        };
    }

    private <T> SingleResultCallback<T> onErrorIf(
            final Function<Throwable, Boolean> condition,
            final SingleResultCallback<T> callback1,
            final SingleResultCallback<T> callback2) {
        return (T r, Throwable e) -> {
            if (e != null && condition.apply(e)) {
                callback1.onResult(r, e);
            } else {
                callback2.onResult(r, e);
            }
        };
    }


    private <T> void sendAndReceiveAsync1(final String message, final SingleResultCallback<T> callback) {
        sendAndReceiveInternalAsync(message, (T r, Throwable e) -> {
            if (triggers(e)) {
                reauthAsync((r2, e2) -> {
                    if (e2 != null) {
                        callback.onResult(null, e2);
                    } else {
                        sendAndReceiveInternalAsync(message, callback);
                    }
                });
            } else {
                callback.onResult(r, e);
            }
        });
    }



    private AsyncFunction<Void, Void> reauthAsync2() {
        return (v,c) -> {
            reauthAsync2x(c);
        };
    }

    private void reauthAsync2x(final SingleResultCallback<Void> c) {
        System.out.println("reauth");
        c.onResult(null, null);
    }

    private <T> void reauthAsync(final SingleResultCallback<T> callback) {
        System.out.println("reauth");
        callback.onResult(null, null);
    }
    private void reauth() {
        System.out.println("reauth");
    }


    private void sendAndReceiveInternal(final String message) {
        System.out.println("internal-throw: " + message);
        throw new RuntimeException();
    }
    private <T> void sendAndReceiveInternalAsync(final String message, final SingleResultCallback<T> callback) {
        try {
            System.out.println("internal-throw: " + message);
            throw new RuntimeException();
        } catch (Exception e) {
            callback.onResult(null, e);
        }
    }
    private AsyncFunction<Void, Void> sendAndReceiveInternalAsync2(final String message) {
        return (v, c) -> {
            try {
                System.out.println("internal-throw: " + message);
                throw new RuntimeException();
            } catch (Exception e) {
                c.onResult(null, e);
            }
        };
    }


    private Boolean triggers(final Throwable e) {
        System.out.println("trigger-check");
        return true;
    }



    @Test
    public void abcTest() throws ExecutionException, InterruptedException {

        // we have some normal function
        System.out.println(functionSync());

        // and some async function, taking a callback
        functionAsync((Integer i, Throwable t) -> System.out.println(i));

        // these can be wrapped and converted, from sync to async and vice-versa

        System.out.println(functionSyncB());
        functionAsyncB((Integer i, Throwable t) -> System.out.println(i));
    }

    public static Integer functionSync() {
        try {
            return Integer.parseInt("1");
        } catch (NumberFormatException e) {
            throw e;
        }
    }

    public static void functionAsync(final SingleResultCallback<Integer> callback) {
        try {
            int result = Integer.parseInt("1");
            callback.onResult(result, null);
        } catch (Exception e) {
            callback.onResult(null, e);
        }
    }


    public static Integer functionSyncB() throws ExecutionException, InterruptedException {

        CompletableFuture<Integer> result = new CompletableFuture<>();

        functionAsync((Integer i, Throwable t) -> {
            if (t == null) {
                result.complete(i);
            } else {
                result.completeExceptionally(t);
            }
        });
        return result.get();
    }

    public static void functionAsyncB(final SingleResultCallback<Integer> callback) {
        try {
            Integer result = functionSync();
            callback.onResult(result, null);
        } catch (Exception e) {
            callback.onResult(null, e);
        }
    }


}
