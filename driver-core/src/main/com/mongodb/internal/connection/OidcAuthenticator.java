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
import com.mongodb.MongoCredential.IdPServerResponse;
import com.mongodb.MongoException;
import com.mongodb.MongoSecurityException;
import com.mongodb.ServerAddress;
import com.mongodb.ServerApi;
import com.mongodb.connection.ClusterConnectionMode;
import com.mongodb.connection.ConnectionDescription;
import com.mongodb.internal.async.SingleResultCallback;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static com.mongodb.AuthenticationMechanism.MONGODB_OIDC;
import static com.mongodb.MongoCredential.ALLOWED_HOSTS;
import static com.mongodb.MongoCredential.DEFAULT_ALLOWED_HOSTS;
import static com.mongodb.MongoCredential.PROVIDER_NAME;
import static com.mongodb.MongoCredential.REFRESH_TOKEN_CALLBACK;
import static com.mongodb.MongoCredential.REQUEST_TOKEN_CALLBACK;
import static com.mongodb.MongoCredential.RefreshCallback;
import static com.mongodb.MongoCredential.RequestCallback;
import static com.mongodb.assertions.Assertions.notNull;
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

        // TODO-OIDC ensure these are of correct type?

        RequestCallback requestCallback = credential.getMechanismProperty(REQUEST_TOKEN_CALLBACK, null);
        Object mechanismProperty = credential.getMechanismProperty(REFRESH_TOKEN_CALLBACK, null);
        RefreshCallback refreshCallback = (RefreshCallback) mechanismProperty;
        boolean automaticAuthentication = requestCallback == null;

        return automaticAuthentication
                ? new OidcAutomaticSaslClient(mongoCredentialWithCache)
                : new OidcCallbackSaslClient(mongoCredentialWithCache, requestCallback, refreshCallback, serverAddress);
    }


    @Override
    public void authenticate(final InternalConnection connection, final ConnectionDescription connectionDescription) {
        super.authenticate(connection, connectionDescription);
    }

    @Override
    void authenticateAsync(
            final InternalConnection connection,
            final ConnectionDescription connectionDescription,
            final SingleResultCallback<Void> callback) {
        super.authenticateAsync(connection, connectionDescription, callback);
    }


    private static class OidcCacheEntry {
        @Nullable
        private final String accessToken;
        @Nullable
        private final Instant expiry;
        @Nullable
        private final String refreshToken;
        @Nullable
        private final IdpServerInfo idpServerInfo;

        OidcCacheEntry(
                @Nullable final IdpServerInfo idpServerInfo,
                @Nullable final Instant expiry,
                final IdPServerResponse tokenResult) {
            this.accessToken = tokenResult.getAccessToken();
            this.idpServerInfo = idpServerInfo;
            this.expiry = expiry;
            this.refreshToken = tokenResult.getRefreshToken();
        }

        public boolean isExpired() {
            return expiry == null || Instant.now().isAfter(expiry);
        }

        public final BsonDocument toBsonDocument() {
            return new BsonDocument().append("jwt", new BsonString(accessToken));
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
        private final ServerAddress serverAddress;

        OidcCallbackSaslClient(
                final MongoCredentialWithCache mongoCredentialWithCache,
                final RequestCallback requestCallback,
                @Nullable final RefreshCallback refreshCallback,
                final ServerAddress serverAddress) {
            super(mongoCredentialWithCache);
            this.requestCallback = requestCallback;
            this.refreshCallback = refreshCallback;
            this.serverAddress = serverAddress;
        }

        @Override
        public boolean isComplete() {
            return getStep() >= 2;
        }

        @Override
        public byte[] evaluateChallengeInternal(final byte[] challenge) {
            return getCredentialWithCache().withLock(() -> evaluate(challenge));
        }

        private byte[] evaluate(final byte[] challenge) {
            OidcCacheEntry cached = getCredentialWithCache().getFromCache(OIDC_CACHE_KEY, OidcCacheEntry.class);

            if (cached != null) {
                if (!cached.isExpired()) {
                    return toBson(cached.toBsonDocument());
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

            String issuer = getString(c, "issuer");
            String clientId = getString(c, "clientId");
            notNull("issuer", issuer);
            notNull("clientId", clientId);

            IdpServerInfo serverInfo = new IdpServerInfo(
                    issuer,
                    clientId,
                    getStringArray(c, "requestScopes"));

            IdPServerResponse result = invokeRequestCallback(serverInfo);

            return handleResult(serverInfo, result);
        }

        @NotNull
        private IdPServerResponse invokeRequestCallback(final IdpServerInfo serverInfo) {
            MongoCredential credential = getCredential();
            validateAllowedHosts(credential);
            return requestCallback.onRequest(
                    credential.getUserName(),
                    serverInfo,
                    CALLBACK_TIMEOUT_SECONDS);
        }

        private void validateAllowedHosts(final MongoCredential credential) {
            List<String> allowedHosts = credential.getMechanismProperty(ALLOWED_HOSTS, DEFAULT_ALLOWED_HOSTS);
            notNull(ALLOWED_HOSTS, allowedHosts);
            String host = serverAddress.getHost();
            boolean permitted = allowedHosts.stream().anyMatch(allowedHost -> {
                if (allowedHost.startsWith("*.")) {
                    String ending = allowedHost.substring(1);
                    return host.endsWith(ending);
                } else if (allowedHost.contains("*")) {
                    throw new IllegalArgumentException(
                            "Allowed host " + allowedHost + " contains invalid wildcard");
                } else {
                    return host.equals(allowedHost);
                }
            });
            if (!permitted) {
                throw new MongoSecurityException(
                        credential, "Host not permitted by " + ALLOWED_HOSTS + ": " + host);
            }
        }

        @Nullable
        private static String getString(final BsonDocument document, final String key) {
            if (!document.containsKey(key) || !document.isString(key)) {
                return null;
            }
            return document.getString(key).getValue();
        }

        @Nullable
        private static List<String> getStringArray(final BsonDocument document, final String key) {
            if (!document.containsKey(key) || document.isArray(key)) {
                return null;
            }
            List<String> result = document.getArray(key).getValues().stream()
                    // ignore non-string values from server, rather than error
                    .filter(v -> v.isString())
                    .map(v -> v.asString().getValue())
                    .collect(Collectors.toList());
            return Collections.unmodifiableList(result);
        }

        private byte[] refreshableTokensFromCacheToServer(final OidcCacheEntry cached) {
            IdPServerResponse result;
            if (refreshCallback == null) {
                result = invokeRequestCallback(cached.idpServerInfo);
            } else {
                result = refreshCallback.onRefresh(
                        getCredential().getUserName(),
                        cached.idpServerInfo,
                        cached.refreshToken,
                        CALLBACK_TIMEOUT_SECONDS);
            }
            return handleResult(cached.idpServerInfo, result);
        }

        private byte[] handleResult(
                final IdpServerInfo serverInfo,
                @Nullable final IdPServerResponse tokens) {
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

            return toBson(new BsonDocument().append("jwt", new BsonString(entry.accessToken)));
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
