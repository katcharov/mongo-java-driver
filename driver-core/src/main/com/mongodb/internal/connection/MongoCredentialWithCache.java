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

package com.mongodb.internal.connection;

import com.mongodb.AuthenticationMechanism;
import com.mongodb.MongoCredential;
import com.mongodb.internal.Locks;
import com.mongodb.lang.Nullable;

import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static com.mongodb.internal.connection.OidcAuthenticator.*;

/**
 * <p>This class is not part of the public API and may be removed or changed at any time</p>
 */
public class MongoCredentialWithCache {
    private final MongoCredential credential;
    private final SingleValueCache cache;

    public MongoCredentialWithCache(final MongoCredential credential) {
        this(credential, null);
    }

    private MongoCredentialWithCache(final MongoCredential credential, @Nullable final SingleValueCache cache) {
        this.credential = credential;
        this.cache = cache != null ? cache : new SingleValueCache();
    }

    public MongoCredentialWithCache withMechanism(final AuthenticationMechanism mechanism) {
        return new MongoCredentialWithCache(credential.withMechanism(mechanism), cache);
    }

    @Nullable
    public AuthenticationMechanism getAuthenticationMechanism() {
        return credential.getAuthenticationMechanism();
    }

    public MongoCredential getCredential() {
        return credential;
    }

    @Nullable
    public <T> T getFromCache(final Object key, final Class<T> clazz) {
        return clazz.cast(cache.get(key));
    }

    /**
     * Putting a key and value will overwrite any prior key and value.
     */
    public void putInCache(final Object key, final Object value) {
        cache.set(key, value);
    }

    public OidcCacheEntry getOidcCacheEntry() {
        System.out.println("FROM CACHE*: " + Thread.currentThread().getName() + "--" + cache.oidcCacheEntry);
        return cache.oidcCacheEntry;
    }

    public void setOidcCacheEntry(final OidcCacheEntry oidcCacheEntry) {
        System.out.println("INTO CACHE*: "  + Thread.currentThread().getName() + "--" + oidcCacheEntry);
        this.cache.oidcCacheEntry = oidcCacheEntry;
    }

    public void clearCache() {
        cache.clear();
    }

    public <V> V withLock(final Supplier<V> k) {
        try {

            System.out.println("LOCKED "  + Thread.currentThread().getName() + "--" + cache.cacheKey);
            return Locks.withLock(cache.lock, k);
        } finally {

            System.out.println("UNLOCKED "  + Thread.currentThread().getName() + "--" + cache.cacheKey);
        }
    }

    static class SingleValueCache {
        private final ReentrantLock lock = new ReentrantLock();
        private Object cacheKey;
        private Object cacheValue;

        private volatile OidcCacheEntry oidcCacheEntry = new OidcCacheEntry();

        Object get(final Object key) {
            return Locks.withLock(lock, () -> {
                if (cacheKey != null && cacheKey.equals(key)) {
                    return cacheValue;
                }
                return null;
            });
        }

        void set(final Object key, final Object value) {
            Locks.withLock(lock, () -> {
                cacheKey = key;
                cacheValue = value;
            });
        }

        public void clear() {
            Locks.withLock(lock, () -> {
                cacheKey = null;
                cacheValue = null;
            });
        }
    }
}

