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
import com.mongodb.MongoCommandException;
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
import java.util.function.Function;
import java.util.function.Supplier;
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
import static com.mongodb.internal.connection.InternalStreamConnection.triggersReauthentication;
import static java.lang.String.format;

/**
 * <p>This class is not part of the public API and may be removed or changed at any time</p>
 */
public class OidcAuthenticator extends SaslAuthenticator {
    private static final int CALLBACK_TIMEOUT_SECONDS = (int) TimeUnit.MINUTES.toSeconds(5);

    public static final String AWS_WEB_IDENTITY_TOKEN_FILE = "AWS_WEB_IDENTITY_TOKEN_FILE";
    
    private volatile String connectionLastAccessToken = null;

    private int refreshState = 0;
    private ServerAddress serverAddress;

    private BsonDocument speculativeAuthenticateResponse;

    public Function<byte[], byte[]> evaluateChallengeFunction;

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
        this.serverAddress = serverAddress;
        RequestCallback requestCallback = getRequestCallback();
        boolean automaticAuthentication = requestCallback == null;
        MongoCredentialWithCache mongoCredentialWithCache = getMongoCredentialWithCache();
        System.out.println("creating sasl client");
        return automaticAuthentication
                ? new OidcAutomaticSaslClient(mongoCredentialWithCache)
                : new OidcCallbackSaslClient(mongoCredentialWithCache);
    }

    @Nullable
    public BsonDocument createSpeculativeAuthenticateCommand(final InternalConnection connection) {
        if (connection.opened()) { // TODO-OIDC
            return null;
        }



        try {
//            byte[] outToken = evaluateChallengeFunction.apply(new byte[0]);

            byte[] outToken = evaluate(new byte[0]);

//            String accessToken = getValidCachedAccessToken();
//            if (accessToken != null) {
//                outToken = sendJwt(accessToken);
//            } else {
//                authLock(connection, connection.getDescription());
//            }


            BsonDocument startDocument = createSaslStartCommandDocument(outToken)
                    .append("db", new BsonString(getMongoCredential().getSource()));
            appendSaslStartOptions(startDocument);
            return startDocument;
        } catch (Exception e) {
            throw wrapException(e);
        }
    }

    @Nullable
    public BsonDocument getSpeculativeAuthenticateResponse() {
        // response should only be read once
        BsonDocument response = speculativeAuthenticateResponse;
        this.speculativeAuthenticateResponse = null;
        return response;
    }

    public void setSpeculativeAuthenticateResponse(@Nullable final BsonDocument response) {
        speculativeAuthenticateResponse = response;
    }

    @Nullable
    private RefreshCallback getRefreshCallback() {
        // TODO-OIDC ensure these are of correct type?
        return getMongoCredentialWithCache()
                .getCredential()
                .getMechanismProperty(REFRESH_TOKEN_CALLBACK, null);
    }

    @Nullable
    private RequestCallback getRequestCallback() {
        return getMongoCredentialWithCache()
                .getCredential()
                .getMechanismProperty(REQUEST_TOKEN_CALLBACK, null);
    }



    @Override
    public <T> T attemptUnderAuthentication(
            final InternalConnection internalConnection,
            final ConnectionDescription connectionDescription,
            final Supplier<T> retryableOperation) {
        try {
            return retryableOperation.get();
        } catch (MongoCommandException e) {
            if (triggersReauthentication(e)) {
                refreshState = 0;
                authLock(internalConnection, connectionDescription);
                return retryableOperation.get();
            }
            throw e;
        }
    }

    @Override
    public void authenticate(final InternalConnection connection, final ConnectionDescription connectionDescription) {

        if (connection.opened()) {
            // method must only be called during original handshake; fail otherwise
            throw new UnsupportedOperationException();
        }
        // this method "wraps" the default authentication method in custom OIDC retry logic
        String accessToken = getValidCachedAccessToken();
        if (accessToken != null) {
            try {
                // TODO-OIDC If this is the handshake, send it under speculative auth. If the response lacks “speculativeAuthenticate”, then speculative authentication has failed: clear the connection’s Access Token and enter AUTHLOCK(Connection Access Token).
                authenticateUsing(connection, connectionDescription, (bytes) -> sendJwt(accessToken));
            } catch (MongoCommandException e) {
                if (InternalStreamConnection.triggersRetry(e)) {
                    authLock(connection, connectionDescription);
                }
            }
        } else {
            authLock(connection, connectionDescription);
        }
    }

    private void authenticateUsing(
            final InternalConnection connection,
            final ConnectionDescription connectionDescription,
            final Function<byte[], byte[]> evaluateChallengeFunction) {
        this.evaluateChallengeFunction = evaluateChallengeFunction;
        super.authenticate(connection, connectionDescription);
    }

    private void authLock(final InternalConnection connection, final ConnectionDescription connectionDescription) {
        MongoCredentialWithCache mongoCredentialWithCache = getMongoCredentialWithCache();
        mongoCredentialWithCache.withLock(() -> {
            while (true) {
                try {
                    authenticateUsing(connection, connectionDescription, (challenge) -> evaluate(challenge));
                    break;
                } catch (MongoCommandException | MongoSecurityException e) {
                    OidcCacheEntry cacheEntry = mongoCredentialWithCache.getOidcCacheEntry();
                    if (InternalStreamConnection.triggersRetry(e)) {
                        prepareRetry(e, cacheEntry);
                    } else {
                        throw e;
                    }
                }
            }
            return null;
        });
    }

    private byte[] evaluate(final byte[] challenge) {
        MongoCredentialWithCache mongoCredentialWithCache = getMongoCredentialWithCache();
        OidcCacheEntry cacheEntry = mongoCredentialWithCache.getOidcCacheEntry();
        String cachedAccessToken = getValidCachedAccessToken();
        String invalidConnectionAccessToken = connectionLastAccessToken;
        String cachedRefreshToken = cacheEntry.refreshToken;
        IdpServerInfo cachedIdpServerInfo = cacheEntry.idpServerInfo;

        if (cachedAccessToken != null) {
            boolean cachedTokenIsInvalid = cachedAccessToken.equals(invalidConnectionAccessToken);
            if (cachedTokenIsInvalid) {
                System.out.println("clearing invalid access token");
                mongoCredentialWithCache.setOidcCacheEntry(cacheEntry.clearAccessToken());
                cachedAccessToken = null;
            }
        }
        RefreshCallback refreshCallback = getRefreshCallback();
        if (cachedAccessToken != null) {
            System.out.println(">>> start 1, using cached JWT " + Thread.currentThread().getName() + "--");
            refreshState = 1;
            return sendJwt(cachedAccessToken);
        } else if (refreshCallback != null && cachedRefreshToken != null && cachedIdpServerInfo != null) {
            System.out.println(">>> start 2, calling onRefresh " + Thread.currentThread().getName() + "--");
            refreshState = 2;
            // Invoke Refresh Callback using cached Refresh Token
            IdPServerResponse result = refreshCallback.onRefresh(
                    getMongoCredential().getUserName(),
                    cachedIdpServerInfo,
                    cachedRefreshToken,
                    CALLBACK_TIMEOUT_SECONDS);
            // Store the results in the cache.
            return handleCallbackResult(cachedIdpServerInfo, result);
        } else {
            if (challenge.length == 0) {
                // occurs when speculative fails
                refreshState = 0;
            }
            // cache is empty
            if (refreshState != 3) {
                System.out.println(">>> start 3 " + Thread.currentThread().getName() + "--");
                refreshState = 3;
                return usernameToServer(mongoCredentialWithCache.getCredential().getUserName());
            } else {
                System.out.println(">>> start 4 - putting jwt into cache " + Thread.currentThread().getName() + "--");
                refreshState = 4;

                IdpServerInfo serverInfo = getIdpServerInfo(challenge);
                IdPServerResponse result = invokeRequestCallback(serverInfo);
                return handleCallbackResult(serverInfo, result);
            }
        }
    }

    private void prepareRetry(final MongoException e, final OidcCacheEntry cacheEntry) {
        MongoCredentialWithCache mongoCredentialWithCache = getMongoCredentialWithCache();
        if (refreshState == 1) {
            System.out.println(">>> retry 1");
            // a cached access token failed
            // clear the cached access token
            mongoCredentialWithCache.setOidcCacheEntry(cacheEntry
                    .clearAccessToken());
        } else if (refreshState == 2) {
            System.out.println(">>> retry 2");
            // a refresh token failed
            // clear the cached access and refresh tokens
            mongoCredentialWithCache.setOidcCacheEntry(cacheEntry
                    .clearAccessToken()
                    .clearRefreshToken());
        } else {
            System.out.println(">>> retry 3&4 - failed");
            // a clean-restart failed
            throw e;
        }
    }

    @Override
    void authenticateAsync(
            final InternalConnection connection,
            final ConnectionDescription connectionDescription,
            final SingleResultCallback<Void> callback) {
        super.authenticateAsync(connection, connectionDescription, callback);
    }

    @Nullable
    private String getValidCachedAccessToken() {
        MongoCredentialWithCache mongoCredentialWithCache = getMongoCredentialWithCache();
        OidcCacheEntry cacheEntry = mongoCredentialWithCache.getOidcCacheEntry();
        String cachedAccessToken = cacheEntry.accessToken;
        if (cachedAccessToken == null) {
            return null;
        }
        if (cacheEntry.isExpired()) {
            return mongoCredentialWithCache.withLock(() -> {
                OidcCacheEntry mostRecentCacheEntry = mongoCredentialWithCache.getOidcCacheEntry();
                if (mostRecentCacheEntry.isExpired()) {
                    mongoCredentialWithCache.setOidcCacheEntry(mostRecentCacheEntry.clearAccessToken());
                    return null;
                } else {
                    return mostRecentCacheEntry.accessToken;
                }
            });
        }
        return cachedAccessToken;
    }

    public static class OidcCacheEntry {
        @Nullable
        private final String accessToken;
        @Nullable
        private final Instant expiry;
        @Nullable
        private final String refreshToken;
        @Nullable
        private final IdpServerInfo idpServerInfo;

        @Override
        public String toString() {
            return "OidcCacheEntry{" +
                    "accessToken='" + (accessToken == null ? null : accessToken.hashCode()) + '\'' +
                    ",\n expiry=" + expiry +
                    ",\n refreshToken='" + refreshToken + '\'' +
                    ",\n idpServerInfo=" + idpServerInfo + // TODO-OIDC \n
                    '}';
        }

        OidcCacheEntry(
                @Nullable final IdpServerInfo idpServerInfo,
                final IdPServerResponse tokens) {
            this(
                    tokens.getAccessToken(),
                    tokens.getExpiresInSeconds() == null
                            ? null
                            : Instant.now().plusSeconds(tokens.getExpiresInSeconds())
                            .minus(5, ChronoUnit.MINUTES),
                    tokens.getRefreshToken(),
                    idpServerInfo);
        }

        public OidcCacheEntry() {
            this(null, null, null, null);
        }

        private OidcCacheEntry(
                @Nullable final String accessToken,
                @Nullable final Instant expiry,
                @Nullable final String refreshToken,
                @Nullable final IdpServerInfo idpServerInfo) {
            this.accessToken = accessToken;
            this.expiry = expiry;
            this.refreshToken = refreshToken;
            this.idpServerInfo = idpServerInfo;
        }

        public boolean isExpired() {
            return expiry == null || Instant.now().isAfter(expiry);
        }

        public OidcCacheEntry clearAccessToken() {
            return new OidcCacheEntry(
                    null,
                    null,
                    this.refreshToken,
                    this.idpServerInfo);
        }

        public OidcCacheEntry clearRefreshToken() {
            return new OidcCacheEntry(
                    this.accessToken,
                    this.expiry,
                    null,
                    null);
        }
    }

    private abstract static class OidcSaslClient extends SaslClientImpl {
        private final MongoCredentialWithCache credentialWithCache;
        private int step = 0;

        OidcSaslClient(final MongoCredentialWithCache mongoCredentialWithCache) {
            super(mongoCredentialWithCache.getCredential());
            this.credentialWithCache = mongoCredentialWithCache;
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

    private class OidcCallbackSaslClient extends OidcSaslClient {

        OidcCallbackSaslClient(final MongoCredentialWithCache mongoCredentialWithCache) {
            super(mongoCredentialWithCache);
        }

        @Override
        public boolean isComplete() {
            return refreshState != 3;
        }

        @Override
        public byte[] evaluateChallengeInternal(final byte[] challenge) {
            return evaluateChallengeFunction.apply(challenge);
        }
    }


    //        private byte[] refreshableTokensFromCacheToServer(final OidcCacheEntry cached) {
//            IdPServerResponse result;
//            if (refreshCallback == null) {
//                result = invokeRequestCallback(cached.idpServerInfo);
//            } else {
//                result = refreshCallback.onRefresh(
//                        getCredential().getUserName(),
//                        cached.idpServerInfo,
//                        cached.refreshToken,
//                        CALLBACK_TIMEOUT_SECONDS);
//            }
//            return handleCallbackResult(cached.idpServerInfo, result);
//        }
    private byte[] usernameToServer(@Nullable final String username) {
        BsonDocument document = new BsonDocument();
        if (username != null) {
            document = document.append("n", new BsonString(username));
        }
        return toBson(document);
    }
    private byte[] handleCallbackResult(
            final IdpServerInfo serverInfo,
            @Nullable final IdPServerResponse tokens) {
        if (tokens == null) {
            throw new MongoConfigurationException("Result of callback must not be null");
        }
        OidcCacheEntry newEntry = new OidcCacheEntry(serverInfo, tokens);
        getMongoCredentialWithCache().setOidcCacheEntry(newEntry);
        return sendJwt(tokens.getAccessToken());
    }

    @NotNull
    private IdpServerInfo getIdpServerInfo(final byte[] challenge) {
        BsonDocument c = new RawBsonDocument(challenge);

        String issuer = getString(c, "issuer");
        String clientId = getString(c, "clientId");
        notNull("issuer", issuer);
        notNull("clientId", clientId);

        IdpServerInfo serverInfo = new IdpServerInfo(
                issuer,
                clientId,
                getStringArray(c, "requestScopes"));
        return serverInfo;
    }

    private IdPServerResponse invokeRequestCallback(final IdpServerInfo serverInfo) {
        MongoCredential credential = getMongoCredential();
        validateAllowedHosts(credential);
        return getRequestCallback().onRequest(
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
    private String getString(final BsonDocument document, final String key) {
        if (!document.containsKey(key) || !document.isString(key)) {
            return null;
        }
        return document.getString(key).getValue();
    }

    @Nullable
    private List<String> getStringArray(final BsonDocument document, final String key) {
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


    @NotNull
    private byte[] sendJwt(final String accessToken) {
        System.out.println("SENDING JWT " + Thread.currentThread().getName() + "--");
        connectionLastAccessToken = accessToken;
        return toBson(new BsonDocument().append("jwt", new BsonString(accessToken)));
    }

    protected static byte[] toBson(final BsonDocument document) {
        byte[] bytes;
        BasicOutputBuffer buffer = new BasicOutputBuffer();
        new BsonDocumentCodec().encode(new BsonBinaryWriter(buffer), document, EncoderContext.builder().build());
        bytes = new byte[buffer.size()];
        System.arraycopy(buffer.getInternalBuffer(), 0, bytes, 0, buffer.getSize());
        return bytes;
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
