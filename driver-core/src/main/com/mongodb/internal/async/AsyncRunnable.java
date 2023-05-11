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

package com.mongodb.internal.async;

import org.jetbrains.annotations.NotNull;

import java.util.function.Function;

public interface AsyncRunnable { // TODO-OIDC

    @NotNull
    static AsyncRunnable runnable() {
        return (c) -> c.onResult(null, null);
    }

    void invoke(SingleResultCallback<Void> continuation); // NoResultCallback

    default AsyncRunnable run(final AsyncRunnable callable) {
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

    default <T> AsyncSupplier<T> supply(final AsyncSupplier<T> supplier) {
        return (c) -> {
            this.invoke((r, e) -> {
                if (e != null) {
                    c.onResult(null, e);
                } else {
                    supplier.invoke(c);
                }
            });
        };
    }

    default AsyncRunnable onErrorIf(
            final Function<Throwable, Boolean> errorCheck,
            final AsyncRunnable callable) {
        return (callback) -> this.invoke((r, e) -> {
            if (e != null && errorCheck.apply(e)) {
                callable.invoke(callback);
            } else {
                callback.onResult(r, null);
            }
        });
    }
}