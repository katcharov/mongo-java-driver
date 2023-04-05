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
import com.mongodb.MongoClientException;
import com.mongodb.MongoConfigurationException;
import com.mongodb.MongoCredential;
import com.mongodb.MongoCredential.IdpServerInfo;
import com.mongodb.MongoCredential.OidcTokens;
import com.mongodb.MongoException;
import com.mongodb.ServerAddress;
import com.mongodb.ServerApi;
import com.mongodb.connection.ClusterConnectionMode;
import com.mongodb.lang.Nullable;
import org.bson.BsonBinaryWriter;
import org.bson.BsonDocument;
import org.bson.BsonString;
import org.bson.RawBsonDocument;
import org.bson.codecs.BsonDocumentCodec;
import org.bson.codecs.EncoderContext;
import org.bson.io.BasicOutputBuffer;
import org.jetbrains.annotations.NotNull;

import javax.security.sasl.SaslClient;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.mongodb.AuthenticationMechanism.MONGODB_OIDC;
import static com.mongodb.MongoCredential.PROVIDER_NAME;
import static com.mongodb.MongoCredential.REFRESH_TOKEN_CALLBACK;
import static com.mongodb.MongoCredential.REQUEST_TOKEN_CALLBACK;
import static com.mongodb.MongoCredential.RefreshCallback;
import static com.mongodb.MongoCredential.RequestCallback;
import static java.lang.String.format;

/**
 * <p>This class is not part of the public API and may be removed or changed at any time</p>
 */
public class OidcAuthenticator extends SaslAuthenticator {
    private static final int CALLBACK_TIMEOUT_SECONDS = (int) TimeUnit.MINUTES.toSeconds(5);

    public static final String AWS_WEB_IDENTITY_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";

    private static final Object OIDC_CACHE_KEY = "OIDC";

    public OidcAuthenticator(
            final MongoCredentialWithCache credential,
            final ClusterConnectionMode clusterConnectionMode,
            @Nullable final ServerApi serverApi) {
        super(credential, clusterConnectionMode, serverApi);

        if (getMongoCredential().getAuthenticationMechanism() != MONGODB_OIDC) {
            throw new MongoException("Incorrect mechanism: " + getMongoCredential().getMechanism());
        }
    }

    @Override
    public String getMechanismName() {
        return MONGODB_OIDC.getMechanismName();
    }

    @Override
    protected SaslClient createSaslClient(final ServerAddress serverAddress) {
        MongoCredentialWithCache mongoCredentialWithCache = getMongoCredentialWithCache();
        MongoCredential credential = mongoCredentialWithCache.getCredential();

        RequestCallback requestCallback = credential.getMechanismProperty(REQUEST_TOKEN_CALLBACK, null);
        RefreshCallback refreshCallback = credential.getMechanismProperty(REFRESH_TOKEN_CALLBACK, null);
        boolean automaticAuthentication = requestCallback == null;

        return automaticAuthentication
                ? new OidcAutomaticSaslClient(mongoCredentialWithCache)
                : new OidcCallbackSaslClient(mongoCredentialWithCache, requestCallback, refreshCallback);
    }


    private static class OidcCacheEntry {
        private final IdpServerInfo idpServerInfo;
        @Nullable
        private final Instant expiry;
        private final OidcTokens oidcTokens;
        private Instant lastAccess;

        OidcCacheEntry(
                final IdpServerInfo idpServerInfo,
                @Nullable final Instant expiry,
                final OidcTokens tokenResult) {
            this.idpServerInfo = idpServerInfo;
            this.expiry = expiry;
            this.oidcTokens = tokenResult;
            this.lastAccess = Instant.now();
        }

        public boolean isExpired() {
            return expiry == null || Instant.now().isAfter(expiry);
        }

        /**
         * Not thread safe; must be called within cache lock
         */
        public void onAccess() {
            lastAccess = Instant.now();
        }

        public boolean isValid() {
            // A cache value is considered valid if it has been accessed in the past 5 hours
            Instant expiry = lastAccess.plus(5, ChronoUnit.HOURS);
            return expiry.isAfter(Instant.now());
        }
    }

    private abstract static class OidcSaslClient extends SaslClientImpl {
        private final MongoCredentialWithCache credentialWithCache;
        private int step = 0;

        OidcSaslClient(final MongoCredentialWithCache mongoCredentialWithCache) {
            super(mongoCredentialWithCache.getCredential());
            this.credentialWithCache = mongoCredentialWithCache;
        }

        protected byte[] toBson(final BsonDocument document) {
            byte[] bytes;
            BasicOutputBuffer buffer = new BasicOutputBuffer();
            new BsonDocumentCodec().encode(new BsonBinaryWriter(buffer), document, EncoderContext.builder().build());
            bytes = new byte[buffer.size()];
            System.arraycopy(buffer.getInternalBuffer(), 0, bytes, 0, buffer.getSize());
            return bytes;
        }

        @Override
        public final byte[] evaluateChallenge(final byte[] challenge) {
            step = getStep() + 1;
            return evaluateChallengeInternal(challenge);
        }

        protected abstract byte[] evaluateChallengeInternal(byte[] challenge);

        protected MongoCredentialWithCache getCredentialWithCache() {
            return credentialWithCache;
        }

        /**
         * The current or last-completed step
         */
        protected int getStep() {
            return step;
        }
    }

    private static class OidcAutomaticSaslClient extends OidcSaslClient {

        OidcAutomaticSaslClient(final MongoCredentialWithCache mongoCredentialWithCache) {
            super(mongoCredentialWithCache);
        }

        @Override
        public boolean isComplete() {
            return getStep() >= 1;
        }

        @Override
        public byte[] evaluateChallengeInternal(final byte[] challenge) {
            return automaticAuthenticationResponse();
        }

        private byte[] automaticAuthenticationResponse() {
            String path = System.getenv(AWS_WEB_IDENTITY_TOKEN_FILE);
            if (path == null) {
                throw new MongoClientException(
                        format("Environment variable must be specified: %s", AWS_WEB_IDENTITY_TOKEN_FILE));
            }
            try {
                // TODO-OIDC only AWS is currently supported
                String token = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
                BsonDocument document = new BsonDocument()
                        .append("jwt", new BsonString(token));
                return toBson(document);
            } catch (IOException e) {
                throw new MongoClientException(format(
                        "Could not read file specified by environment variable: %s at path: %s",
                        AWS_WEB_IDENTITY_TOKEN_FILE, path), e);
            }
        }
    }

    private static class OidcCallbackSaslClient extends OidcSaslClient {
        private final RequestCallback requestCallback;
        private final RefreshCallback refreshCallback;

        OidcCallbackSaslClient(
                final MongoCredentialWithCache mongoCredentialWithCache,
                final RequestCallback requestCallback,
                @Nullable final RefreshCallback refreshCallback) {
            super(mongoCredentialWithCache);
            this.requestCallback = requestCallback;
            this.refreshCallback = refreshCallback;
        }

        @Override
        public boolean isComplete() {
            return getStep() >= 2;
        }

        @Override
        public byte[] evaluateChallengeInternal(final byte[] challenge) {
            return getCredentialWithCache().withLock(() -> evaluate(challenge));
        }

        @NotNull
        private byte[] evaluate(final byte[] challenge) {
            OidcCacheEntry cached = getCredentialWithCache().getFromCache(OIDC_CACHE_KEY, OidcCacheEntry.class);
            if (cached != null && !cached.isValid()) {
                getCredentialWithCache().clearCache();
                cached = null;
            }
            if (cached != null) {
                cached.onAccess();
                if (!cached.isExpired()) {
                    return toBson(cached.oidcTokens.toBsonDocument());
                }
                return refreshableTokensFromCacheToServer(cached);
            }

            if (getStep() == 1) {
                return usernameToServer(getCredential().getUserName());
            } else if (getStep() == 2) {
                return tokensFromInitialCallbackToServer(challenge);
            } else {
                throw new MongoClientException(
                        format("Too many steps involved in the %s negotiation.", getMechanismName()));
            }
        }

        private byte[] usernameToServer(@Nullable final String username) {
            BsonDocument document = new BsonDocument();
            if (username != null) {
                document = document.append("n", new BsonString(username));
            }
            return toBson(document);
        }

        private byte[] tokensFromInitialCallbackToServer(final byte[] challenge) {
            BsonDocument c = new RawBsonDocument(challenge);
            IdpServerInfo serverInfo = new IdpServerInfo(c);

            OidcTokens result = requestCallback.callback(
                    getCredential().getUserName(),
                    serverInfo,
                    123);

            return handleResult(serverInfo, result);
        }

        @NotNull
        private byte[] refreshableTokensFromCacheToServer(final OidcCacheEntry cached) {
            OidcTokens result;
            if (refreshCallback == null) {
                result = requestCallback.callback(
                        getCredential().getUserName(),
                        cached.idpServerInfo,
                        CALLBACK_TIMEOUT_SECONDS);
            } else {
                result = refreshCallback.callback(
                        getCredential().getUserName(),
                        cached.idpServerInfo,
                        cached.oidcTokens,
                        CALLBACK_TIMEOUT_SECONDS);
            }
            return handleResult(cached.idpServerInfo, result);
        }

        private byte[] handleResult(
                final IdpServerInfo serverInfo,
                @Nullable final OidcTokens tokens) {
            if (tokens == null) {
                throw new MongoConfigurationException("Result of callback must not be null");
            }
            Integer expiresInSeconds = tokens.getExpiresInSeconds();
            Instant expiry = expiresInSeconds == null
                    ? null
                    : Instant.now()
                    .plusSeconds(expiresInSeconds)
                    .minus(5, ChronoUnit.MINUTES);

            OidcCacheEntry entry = new OidcCacheEntry(serverInfo, expiry, tokens);
            getCredentialWithCache().putInCache(OIDC_CACHE_KEY, entry);
            return toBson(entry.oidcTokens.toBsonDocument());
        }
    }

    public static final class OidcValidator {
        private OidcValidator() {
        }

        public static void validateOidcCredentialConstruction(
                final String source,
                final Map<String, Object> mechanismProperties) {

            if (!"$external".equals(source)) {
                throw new IllegalArgumentException("source must be '$external'");
            }

            Object device = mechanismProperties.get(PROVIDER_NAME.toLowerCase());
            if (device != null) {
                List<String> devices = Arrays.asList("aws", "azure", "gcp");
                if (!(device instanceof String) || !devices.contains(device)) {
                    throw new IllegalArgumentException(PROVIDER_NAME + " must be one of: " + devices);
                }
            }
        }

        public static void validateCreateOidcCredential(@Nullable final char[] password) {
            // a connection string might contain a password
            if (password != null) {
                throw new IllegalArgumentException("password must not be specified for "
                        + AuthenticationMechanism.MONGODB_OIDC);
            }
        }

        public static void validateBeforeUse(final MongoCredential credential) {
            AuthenticationMechanism mechanism = credential.getAuthenticationMechanism();
            String userName = credential.getUserName();

            if (mechanism == AuthenticationMechanism.MONGODB_OIDC) {
                Object device = credential.getMechanismProperty(PROVIDER_NAME, null);
                if (device == null) {
                    //if (userName == null ) {
                    // TODO-OIDC -  MUST be specified if more than one OIDC provider is configured
                    //throw new IllegalArgumentException("username can not be null");
                    //}
                    Object requestCallback = credential.getMechanismProperty(REQUEST_TOKEN_CALLBACK, null);
                    if (requestCallback == null) {
                        throw new IllegalArgumentException("Either " + PROVIDER_NAME + " or "
                                + REQUEST_TOKEN_CALLBACK + " must be specified");
                    }
                } else {
                    // device workflow
                    if (userName != null) {
                        throw new IllegalArgumentException("username must not be specified when device is specified");
                    }
                }
            }
        }
    }
}
