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

package com.mongodb.client;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.MongoCredential.OidcTokens;
import com.mongodb.MongoCredential.RefreshCallback;
import com.mongodb.MongoSecurityException;
import com.mongodb.internal.connection.TestCommandListener;
import com.mongodb.lang.Nullable;
import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static com.mongodb.MongoCredential.RequestCallback;
import static com.mongodb.client.TestHelper.setEnvironmentVariable;
import static com.mongodb.internal.connection.OidcAuthenticator.AWS_WEB_IDENTITY_TOKEN_FILE;
import static java.lang.System.getenv;
import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static util.ThreadTestHelpers.executeAll;

public class OidcAuthenticationProseTests {

    protected static final String OIDC_URL = "mongodb://localhost/?authMechanism=MONGODB-OIDC";

    protected MongoClient createMongoClient(final MongoClientSettings settings) {
        return MongoClients.create(settings);
    }

    protected void setOidcFile(final String file) {
        setEnvironmentVariable(AWS_WEB_IDENTITY_TOKEN_FILE, "/tmp/tokens/" + file);
    }

    @BeforeEach
    public void beforeEach() {
        setOidcFile("test_user1");
        // In each test, clearing the cache is not required, since there is no global cache
    }

    @ParameterizedTest
    @CsvSource(delimiter = '#', value = {
            // 1.1 to 1.5:
            "test_user1#" + OIDC_URL,
            "test_user1#mongodb://test_user1@localhost/?authMechanism=MONGODB-OIDC",
            "test_user1#mongodb://test_user1@localhost:27018/?authMechanism=MONGODB-OIDC&directConnection=true&readPreference=secondaryPreferred",
            "test_user2#mongodb://test_user2@localhost:27018/?authMechanism=MONGODB-OIDC&directConnection=true&readPreference=secondaryPreferred",
            "invalid#mongodb://localhost:27018/?authMechanism=MONGODB-OIDC&directConnection=true&readPreference=secondaryPreferred",
    })
    public void test1CallbackDrivenAuth(final String file, final String url) {
        boolean shouldFail = file.equals("invalid");
        setOidcFile(file);

        // #. Create a request callback that returns a valid token.
        RequestCallback requestCallback = createCallback();

        // #. Create a client with a url of the form ... and the OIDC request callback.
        MongoClientSettings clientSettings = createClientSettings(url, requestCallback, null);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Perform a find operation ...
            if (shouldFail) { // that fails
                assertThrows(MongoSecurityException.class, () -> performFindOperation(mongoClient));
            } else { // that succeeds
                performFindOperation(mongoClient);
            }
        }
    }

    @ParameterizedTest
    @CsvSource(value = {
            // 1.6, both variants:
            "", // empty list
            "localhost",
    })
    public void test1p6CallbackDrivenAuthAllowedHostsBlocked(final String allowedHostsString) {
        // Create a client that uses the OIDC url and a request callback, and an ALLOWED_HOSTS that contains...
        List<String> allowedHosts = asList(allowedHostsString.split(","));

        // TODO-OIDC add allowedHosts to createOidcCredential
        MongoClientSettings clientSettings = createClientSettings(OIDC_URL, createCallback(), null);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Assert that a find operation fails with a client-side error.
            assertThrows(Exception.class, () -> performFindOperation(mongoClient));
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '#', value = {
            // 2.1 to 2.3:
            "test_user1#mongodb://localhost/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws",
            "test_user1#mongodb://localhost:27018/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws&directConnection=true&readPreference=secondaryPreferred",
            "test_user2#mongodb://localhost:27018/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws&directConnection=true&readPreference=secondaryPreferred",
    })
    public void test2AwsAutomaticAuth(final String file, final String url) {
        setOidcFile(file);
        // #. Create a client with a url of the form ...
        MongoCredential credential = MongoCredential.createOidcCredential("aws");
        ConnectionString connectionString = new ConnectionString(url);
        MongoClientSettings clientSettings = MongoClientSettings.builder()
                .credential(credential)
                .applyConnectionString(connectionString)
                .build();
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Perform a find operation that succeeds.
            performFindOperation(mongoClient);
        }
    }

    @Test
    public void test1p6CallbackDrivenAuthAllowedHostsBlocked() {
        // Create a client with a url of the form ..., and an ALLOWED_HOSTS that is an empty list.
        String url = "mongodb://localhost/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws";
        List<String> allowedHosts = Arrays.asList();
        // Assert that a find operation succeeds.

        // TODO-OIDC complete test and add allowedHosts to createOidcCredential
    }

    // TODO-OIDC 3: callback validation

    @Test
    public void test4p1CachedCredentialsCacheWithRefresh() {
        blockNextFind();

        // #. Create a new client with a request callback that gives credentials that expire in on minute.
        TestCallback requestCallback = createCallback();
        requestCallback.setExpiresInSeconds(60);
        TestCallback refreshCallback = createCallback();
        MongoClientSettings clientSettings = createClientSettings(OIDC_URL, requestCallback, refreshCallback);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            executeAll(2, () -> performFindOperation(mongoClient));
            // #. Ensure that a find operation adds credentials to the cache.
            // #. Ensure that a find operation results in a call to the refresh callback.
            assertEquals(1, requestCallback.getInvocations());
            assertEquals(1, refreshCallback.getInvocations());
            // the refresh invocation will fail if the cached tokens are null
            // so a success implies that credentials were present in the cache
        }
    }

    @Test
    public void test4p2CachedCredentialsCacheWithNoRefresh() {
        blockNextFind();

        // #. Create a new client with a request callback that gives credentials that expire in one minute.
        // #. Ensure that a find operation adds credentials to the cache.
        // #. Close the client.
        // #. Create a new client with a request callback but no refresh callback.
        // #. Ensure that a find operation results in a call to the request callback.

        // this is the same as 4.1, but have no refresh and assert that the request callback is called twice

        TestCallback requestCallback = createCallback();
        requestCallback.setExpiresInSeconds(60);
        MongoClientSettings clientSettings = createClientSettings(OIDC_URL, requestCallback, null);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            executeAll(2, () -> performFindOperation(mongoClient));

            assertEquals(2, requestCallback.getInvocations());
        }
    }

    // 4.3 is skipped:
    // If the driver does not support using callback references or hashes as part of the cache key, skip this test.

    // 4.4 Error clears cache TODO-OIDC

    // 4.5 AWS Automatic workflow does not use cache TODO-OIDC

    // 5   Speculative Authentication TODO-OIDC

    @Test
    public void test6p1ReauthenticationSucceeds() {
        // #. Create request and refresh callbacks that return valid credentials that will not expire soon.
        TestCallback requestCallback = createCallback();
        TestCallback refreshCallback = createCallback();

        // #. Create a client with the callbacks and an event listener capable of listening for SASL commands.
        TestCommandListener commandListener = new TestCommandListener();
        MongoClientSettings clientSettings = createClientSettingsBuilder(OIDC_URL, requestCallback, refreshCallback)
                .addCommandListener(commandListener)
                .build();
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {

            // #. Perform a find operation that succeeds.
            performFindOperation(mongoClient);

            // #. Assert that the refresh callback has not been called.
            assertEquals(0, refreshCallback.getInvocations());

            // #. Force a reauthenication using a failCommand
            failNextFind();

            // reset
            commandListener.reset();

            // #. Perform another find operation that succeeds.
            performFindOperation(mongoClient);

            // #. Assert that the refresh callback has been called once, if possible.
            assertEquals(0, refreshCallback.getInvocations());

            // #. Assert that the ordering of command started events is find, saslStart , find.
            // #. Assert that the ordering of command succeeded events is saslStart, find.
            // #. Assert that a find operation failed once during the command execution.
            assertEquals(Arrays.asList(
                    "find started",
                    "find failed",
                    "saslStart started", // TODO-OIDC these events need to be removed
                    "saslStart succeeded",
                    "saslContinue started",
                    "saslContinue succeeded",
                    "find started",
                    "find succeeded"
            ), commandListener.getEventStrings());
        }
    }

    // TODO-OIDC 6.2, 6.3

    @Test
    public void test6p2ReauthenticationRetriesAndSucceedsWithCache() {
        // #. Create request and refresh callbacks that return valid credentials that will not expire soon.
        TestCallback requestCallback = createCallback();
        TestCallback refreshCallback = createCallback();
        MongoClientSettings clientSettings = createClientSettings(OIDC_URL, requestCallback, refreshCallback);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Perform a find operation that succeeds.
            performFindOperation(mongoClient);

            // #. Force a reauthenication using a failCommand
            failNextFindAndSaslStart();

            // #. Perform a find operation that succeeds.
            performFindOperation(mongoClient);
        }
    }


    @Test
    public void test6p3ReauthenticationRetriesAndFailsWithNoCache() {
        // TODO-OIDC speculative auth
    }

    public MongoClientSettings createClientSettings(
            final String connectionString,
            final RequestCallback requestCallback,
            @Nullable final RefreshCallback refreshCallback) {
        MongoClientSettings.Builder builder = createClientSettingsBuilder(
                connectionString, requestCallback, refreshCallback);
        MongoClientSettings clientSettings = builder.build();

        MongoCredential credential = clientSettings.getCredential();
        if (credential == null) {
            throw new NullPointerException("credential was null");
        }
        assertEquals(
                new ConnectionString(connectionString).getUsername(),
                credential.getUserName());

        return clientSettings;
    }

    protected MongoClientSettings.Builder createClientSettingsBuilder(
            final String connectionString,
            final RequestCallback requestCallback,
            @Nullable final RefreshCallback refreshCallback) {
        MongoCredential credential = MongoCredential.createOidcCredential(
                null,
                requestCallback,
                refreshCallback);
        return MongoClientSettings.builder()
                .credential(credential)
                .applyConnectionString(new ConnectionString(connectionString));
    }

    protected void performFindOperation(final MongoClient mongoClient) {
        mongoClient
                .getDatabase("test")
                .getCollection("test")
                .find()
                .first();
    }

    private void failNextFindAndSaslStart() {
        try (MongoClient mongoClient2 = createMongoClient(createClientSettings(
                "mongodb://localhost/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws", null, null))) {
            failCommand(mongoClient2, 391, 2, "find", "saslStart");
        }
    }

    private void blockCommand(final MongoClient mongoClient, final String command, final int ms) {
        BsonDocument failPointDocument = new BsonDocument("configureFailPoint", new BsonString("failCommand"))
                .append("mode", new BsonDocument("times", new BsonInt32(1)))
                .append("data", new BsonDocument(
                        "failCommands", new BsonArray(asList(new BsonString(command))))
                        .append("blockConnection", new BsonBoolean(true))
                        .append("blockTimeMS", new BsonInt32(ms)));
        mongoClient.getDatabase("admin").runCommand(failPointDocument);
    }

    private void failCommand(final MongoClient mongoClient, final int errCode, final int times, final String... commands) {
        List<BsonString> list = Arrays.stream(commands).map(c -> new BsonString(c)).collect(Collectors.toList());
        BsonDocument failPointDocument = new BsonDocument("configureFailPoint", new BsonString("failCommand"))
                .append("mode", new BsonDocument("times", new BsonInt32(times)))
                .append("data", new BsonDocument(
                        "failCommands", new BsonArray(list))
                        .append("errorCode", new BsonInt32(errCode)));
        mongoClient.getDatabase("admin").runCommand(failPointDocument);
    }

    protected void blockNextFind() {
        try (MongoClient mongoClient = createMongoClient(createClientSettings(
                "mongodb://localhost/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws", null, null))) {
            // #. Create a new client with the same request callback and a refresh callback.
            // Instead:
            // 1. Delay the first find, causing the second find to authenticate a second connection
            blockCommand(mongoClient, "find", 100);
        }
    }

    protected void failNextFind() {
        try (MongoClient mongoClient = createMongoClient(createClientSettings(
                "mongodb://localhost/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws", null, null))) {
            failCommand(mongoClient, 391, 1, "find");
        }
        // TODO-OIDC the driver MUST either use a unique appName or explicitly remove the failCommand after the test to prevent leakage.
    }


    public static class TestCallback implements RequestCallback, RefreshCallback {
        private Integer expiresInSeconds;
        private Integer simulatedDelayInMilliseconds;

        private final AtomicInteger invocations = new AtomicInteger();

        public int getInvocations() {
            return invocations.get();
        }

        @Override
        public synchronized OidcTokens callback(
                @Nullable final String principalName,
                final MongoCredential.IdpServerInfo serverInfo,
                final int timeoutSeconds) {

            invocations.incrementAndGet();
            String path = getenv(AWS_WEB_IDENTITY_TOKEN_FILE);
            String token;
            try {
                simulateDelay();
                token = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
            } catch (IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }

            return new OidcTokens(
                    token,
                    getExpiresInSeconds(),
                    null);
        }

        private void simulateDelay() throws InterruptedException {
            if (simulatedDelayInMilliseconds != null) {
                Thread.sleep(simulatedDelayInMilliseconds);
            }
        }

        @Override
        public OidcTokens callback(
                @Nullable final String principalName,
                final MongoCredential.IdpServerInfo serverInfo,
                @Nullable final OidcTokens tokens, // test against null
                final int timeoutSeconds) {
            if (tokens == null) {
                throw new IllegalArgumentException("tokens were null");
            }
            return this.callback(principalName, serverInfo, timeoutSeconds);
        }

        public Integer getExpiresInSeconds() {
            return expiresInSeconds;
        }

        public void setExpiresInSeconds(final Integer expiresInSeconds) {
            this.expiresInSeconds = expiresInSeconds;
        }

        public void setSimulatedDelayInMilliseconds(final Integer simulatedDelayInMilliseconds) {
            this.simulatedDelayInMilliseconds = simulatedDelayInMilliseconds;
        }
    }

    public TestCallback createCallback() {
        return new TestCallback();
    }

}
