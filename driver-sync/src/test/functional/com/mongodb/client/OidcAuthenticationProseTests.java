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
import com.mongodb.MongoCommandException;
import com.mongodb.MongoConfigurationException;
import com.mongodb.MongoCredential;
import com.mongodb.MongoCredential.IdPServerResponse;
import com.mongodb.MongoCredential.RefreshCallback;
import com.mongodb.MongoSecurityException;
import com.mongodb.event.CommandListener;
import com.mongodb.internal.connection.InternalStreamConnection;
import com.mongodb.internal.connection.TestCommandListener;
import com.mongodb.lang.Nullable;
import org.bson.BsonArray;
import org.bson.BsonBoolean;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonString;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.opentest4j.AssertionFailedError;
import org.opentest4j.MultipleFailuresError;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.mongodb.MongoCredential.ALLOWED_HOSTS;
import static com.mongodb.MongoCredential.PROVIDER_NAME;
import static com.mongodb.MongoCredential.REFRESH_TOKEN_CALLBACK;
import static com.mongodb.MongoCredential.REQUEST_TOKEN_CALLBACK;
import static com.mongodb.MongoCredential.RequestCallback;
import static com.mongodb.client.TestHelper.setEnvironmentVariable;
import static com.mongodb.internal.connection.OidcAuthenticator.AWS_WEB_IDENTITY_TOKEN_FILE;
import static java.lang.System.getenv;
import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static util.ThreadTestHelpers.executeAll;

public class OidcAuthenticationProseTests {


    public static final String TOKEN_DIRECTORY = "/Users/maxim.katcharov/code/drivers-evergreen-tools/.evergreen/auth_oidc/test_tokens/";
    //        "/tmp/tokens/"
    // TODO-OIDC

    protected static final String OIDC_URL = "mongodb://localhost/?authMechanism=MONGODB-OIDC";
    private static final String AWS_OIDC_URL =
            "mongodb://localhost/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws";

    protected MongoClient createMongoClient(final MongoClientSettings settings) {
        return MongoClients.create(settings);
    }

    protected void setOidcFile(final String file) {

        setEnvironmentVariable(AWS_WEB_IDENTITY_TOKEN_FILE, TOKEN_DIRECTORY + file);
    }

    @BeforeEach
    public void beforeEach() {
        setOidcFile("test_user1");
        InternalStreamConnection.RECORD_EVERYTHING = true;
        // In each test, clearing the cache is not required, since there is no global cache
    }

    @AfterEach
    public void afterEach() {
        InternalStreamConnection.RECORD_EVERYTHING = false;
    }

    @ParameterizedTest
    @CsvSource(delimiter = '#', value = {
            // 1.1 to 1.5:
            "test1p1 # test_user1 # " + OIDC_URL,
            "test1p2 # test_user1 # mongodb://test_user1@localhost/?authMechanism=MONGODB-OIDC",
            "test1p3 # test_user1 # mongodb://test_user1@localhost:27018/?authMechanism=MONGODB-OIDC&directConnection=true&readPreference=secondaryPreferred",
            "test1p4 # test_user2 # mongodb://test_user2@localhost:27018/?authMechanism=MONGODB-OIDC&directConnection=true&readPreference=secondaryPreferred",
            "test1p5 # invalid # mongodb://localhost:27018/?authMechanism=MONGODB-OIDC&directConnection=true&readPreference=secondaryPreferred",
    })
    public void xtest1CallbackDrivenAuth(final String name, final String file, final String url) {
        boolean shouldPass = !file.equals("invalid");
        setOidcFile(file);
        // #. Create a request callback that returns a valid token.
        RequestCallback onRequest = createCallback();
        // #. Create a client with a URL of the form ... and the OIDC request callback.
        MongoClientSettings clientSettings = createSettings(url, onRequest, null);
        // #. Perform a find operation that succeeds / fails
        if (shouldPass) {
            performFind(clientSettings);
        } else {
            performFind(
                    clientSettings,
                    MongoCommandException.class,
                    "Command failed with error 18 (AuthenticationFailed)");
        }
    }

    // TODO-OIDC token with null expiry

    @ParameterizedTest
    @CsvSource(delimiter = '#', value = {
            // 1.6, both variants:
            "'' # " + OIDC_URL,
            "example.com # mongodb://localhost/?authMechanism=MONGODB-OIDC&ignored=example.com",
    })
    public void xtest1p6CallbackDrivenAuthAllowedHostsBlocked(final String allowedHosts, final String url) {
        // Create a client that uses the OIDC url and a request callback, and an ALLOWED_HOSTS that contains...
        List<String> allowedHostsList = asList(allowedHosts.split(","));
        MongoClientSettings settings = createSettings(url, createCallback(), null, allowedHostsList, null);
        // #. Assert that a find operation fails with a client-side error.
        performFind(settings, MongoSecurityException.class, "");
    }

    @Test
    public void xtest1p7LockAvoidsExtraCallbackCalls() {
        proveThatConcurrentCallbacksThrow();
        // The test requires that two operations are attempted concurrently.
        // The delay on the next find should cause the initial request to delay
        // and the ensuing refresh to block, rather than entering onRefresh.
        // After blocking, this ensuing refresh thread will enter onRefresh.
        AtomicInteger concurrent = new AtomicInteger();
        TestCallback onRequest = createExpiredCallback().setConcurrentTracker(concurrent);
        TestCallback onRefresh = createCallback().setConcurrentTracker(concurrent);
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            delayNextFind(); // cause both callbacks to be called
            executeAll(2, () -> performFind(mongoClient));
            assertEquals(1, onRequest.getInvocations());
            assertEquals(1, onRefresh.getInvocations());
        }
    }

    public void proveThatConcurrentCallbacksThrow() {
        // ensure that, via delay, test callbacks throw when invoked concurrently
        AtomicInteger c = new AtomicInteger();
        TestCallback request = createCallback().setConcurrentTracker(c).setDelayMs(5);
        TestCallback refresh = createCallback().setConcurrentTracker(c);
        String principalName = "principalName";
        MongoCredential.IdpServerInfo serverInfo = new MongoCredential.IdpServerInfo("issuer", "clientId", asList());
        executeAll(() -> {
            sleep(2);
            assertThrows(RuntimeException.class, () -> {
                refresh.onRefresh(principalName, serverInfo, "refToken", 1234);
            });
        }, () -> {
            request.onRequest(principalName, serverInfo, 1234);
        });
    }

    private void sleep(final long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '#', value = {
            // 2.1 to 2.3:
            "test2p1 # test_user1 # " + AWS_OIDC_URL,
            "test2p2 # test_user1 # mongodb://localhost:27018/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws&directConnection=true&readPreference=secondaryPreferred",
            "test2p3 # test_user2 # mongodb://localhost:27018/?authMechanism=MONGODB-OIDC&authMechanismProperties=PROVIDER_NAME:aws&directConnection=true&readPreference=secondaryPreferred",
    })
    public void xtest2AwsAutomaticAuth(final String name, final String file, final String url) {
        setOidcFile(file);
        // #. Create a client with a url of the form ...
        MongoCredential credential = MongoCredential.createOidcCredential(null)
                .withMechanismProperty(PROVIDER_NAME, "aws");
        MongoClientSettings clientSettings = MongoClientSettings.builder()
                .credential(credential)
                .applyConnectionString(new ConnectionString(url))
                .build();
        // #. Perform a find operation that succeeds.
        performFind(clientSettings);
    }

    @Test
    public void xtest2p4AllowedHostsIgnored() {
        MongoClientSettings settings = createSettings(
                AWS_OIDC_URL, null, null, Arrays.asList(), null);
        performFind(settings);
    }

    @Test
    public void xtest3p1ValidCallbacks() {
        String connectionString = "mongodb://test_user1@localhost/?authMechanism=MONGODB-OIDC";
        String expectedPrincipalName = "test_user1";
        String expectedClientId = "0oadp0hpl7q3UIehP297";
        String expectedIssuer = "https://ebgxby0dw8.execute-api.us-west-1.amazonaws.com/default/mock-identity-config-oidc";
        int expectedSeconds = 5 * 60;


        TestCallback onRequest = createExpiredCallback();
        TestCallback onRefresh = createCallback();
        // #. Verify that the request callback was called with the appropriate
        //    inputs, including the timeout parameter if possible.
        // #. Verify that the refresh callback was called with the appropriate
        //    inputs, including the timeout parameter if possible.
        RequestCallback onRequest2 = (principalName, serverInfo, timeout) -> {
            assertEquals(expectedPrincipalName, principalName);
            assertEquals(expectedClientId, serverInfo.getClientId());
            assertEquals(expectedIssuer, serverInfo.getIssuer());
            //assertEquals(Arrays.asList(""), serverInfo.getRequestScopes()); // TODO-OIDC
            assertEquals(expectedSeconds, timeout);
            return onRequest.onRequest(principalName, serverInfo, timeout);
        };
        RefreshCallback onRefresh2 = (principalName, serverInfo, refreshToken, timeout) -> {
            assertEquals(expectedPrincipalName, principalName);
            assertEquals(expectedClientId, serverInfo.getClientId());
            assertEquals(expectedIssuer, serverInfo.getIssuer());
            //assertEquals(Arrays.asList(""), serverInfo.getRequestScopes()); // TODO-OIDC
            assertEquals(expectedSeconds, timeout);
            assertEquals("refreshToken", refreshToken);
            return onRefresh.onRefresh(principalName, serverInfo, refreshToken, timeout);
        };
        MongoClientSettings clientSettings = createSettings(connectionString, onRequest2, onRefresh2);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            delayNextFind(); // cause both callbacks to be called
            executeAll(2, () -> performFind(mongoClient));
            // Ensure that both callbacks were called
            assertEquals(1, onRequest.getInvocations());
            assertEquals(1, onRefresh.getInvocations());
        }
    }

    @Test
    public void xtest3p2RequestCallbackReturnsNull() {
        //noinspection ConstantConditions
        RequestCallback onRequest = (principalName, serverInfo, timeout) -> null;
        MongoClientSettings settings = this.createSettings(OIDC_URL, onRequest, null);
        performFind(settings, MongoConfigurationException.class, "Result of callback must not be null");
    }

    @Test
    public void xtest3p3RefreshCallbackReturnsNull() {
        TestCallback onRequest = createExpiredCallback().setDelayMs(100);
        //noinspection ConstantConditions
        RefreshCallback onRefresh = (principalName, serverInfo, refreshToken, timeout) -> null;
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            delayNextFind(); // cause both callbacks to be called
            try {
                executeAll(2, () -> performFind(mongoClient));
            } catch (MultipleFailuresError actual) {
                assertEquals(1, actual.getFailures().size());
                assertCause(
                        MongoConfigurationException.class,
                        "Result of callback must not be null",
                        actual.getFailures().get(0));
            }
            assertEquals(1, onRequest.getInvocations());
        }
    }

    @Test
    public void xtest3p4RequestCallbackReturnsInvalidData() {
        // #. Create a client with a request callback that returns data not
        //    conforming to the OIDCRequestTokenResult with missing field(s).
        // #. ... with extra field(s). - not possible
        RequestCallback onRequest = (principalName, serverInfo, timeout) -> {
            //noinspection ConstantConditions
            return new IdPServerResponse(null, null, null);
        };
        // we ensure that the error is propagated
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, null);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            try {
                performFind(mongoClient);
                fail();
            } catch (Exception e) {
                assertCause(IllegalArgumentException.class, "accessToken can not be null", e);
            }
        }
    }

    @Test
    public void xtest3p5RefreshCallbackReturnsInvalidData() {
        TestCallback onRequest = createExpiredCallback();
        RefreshCallback onRefresh = (principalName, serverInfo, refreshToken, timeout) -> {
            //noinspection ConstantConditions
            return new IdPServerResponse(null, null, null);
        };
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            try {
                executeAll(2, () -> performFind(mongoClient));
            } catch (MultipleFailuresError actual) {
                assertEquals(1, actual.getFailures().size());
                assertCause(
                        IllegalArgumentException.class,
                        "accessToken can not be null",
                        actual.getFailures().get(0));
            }
            assertEquals(1, onRequest.getInvocations());
        }
    }

    // 3.6   Refresh Callback Returns Extra Data - not possible

    @Test
    public void xtest4p1CachedCredentialsCacheWithRefresh() {
        // #. Create a new client with a request callback that gives credentials that expire in one minute.
        TestCallback onRequest = createExpiredCallback();
        TestCallback onRefresh = createCallback();
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Create a new client with the same request callback and a refresh callback.
            // Instead:
            // 1. Delay the first find, causing the second find to authenticate a second connection
            delayNextFind(); // cause both callbacks to be called
            executeAll(2, () -> performFind(mongoClient));
            // #. Ensure that a find operation adds credentials to the cache.
            // #. Ensure that a find operation results in a call to the refresh callback.
            assertEquals(1, onRequest.getInvocations());
            assertEquals(1, onRefresh.getInvocations());
            // the refresh invocation will fail if the cached tokens are null
            // so a success implies that credentials were present in the cache
        }
    }

    @Test
    public void xtest4p2CachedCredentialsCacheWithNoRefresh() {
        // #. Create a new client with a request callback that gives credentials that expire in one minute.
        // #. Ensure that a find operation adds credentials to the cache.
        // #. Create a new client with a request callback but no refresh callback.
        // #. Ensure that a find operation results in a call to the request callback.
        TestCallback onRequest = createExpiredCallback();
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, null);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            delayNextFind(); // cause both callbacks to be called
            executeAll(2, () -> performFind(mongoClient));
            // test is the same as 4.1, but no onRefresh, and assert that the onRequest is called twice
            assertEquals(2, onRequest.getInvocations());
        }
    }

    // 4.3   Cache key includes callback - skipped:
    // If the driver does not support using callback references or hashes as part of the cache key, skip this test.

    @Test
    public void busted_test4p4ErrorClearsCache() {
        fail();
//        // #. Create a new client with a valid request callback that
//        //    gives credentials that expire within 5 minutes and
//        //    a refresh callback that gives invalid credentials.
//        TestCallback onRequest = createExpiredCallback();
//        TestCallback onRefresh = new TestCallback() {
//            protected String getNextPath() {
//                return "test_user1_expires";
//            }
//        };
//
//        // #. Ensure that a find operation adds a new entry to the cache.
//
//        // #. Create a new client with the same parameters.
//        // #. Ensure that a subsequent find operation results in a 391 error.
//        // #. Ensure that the cache value cleared.
//        // #. Close the client.
//
//        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
//        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
//
//            delayNextFind();
//            executeAll(2, () -> performFind(mongoClient));
//            assertEquals(1, onRequest.getInvocations());
//            assertEquals(1, onRefresh.getInvocations());
//
//            performFind(mongoClient);
//
//            failCommand(391, 1, "find");
//
//            assertEquals(2, onRequest.getInvocations());
//            assertEquals(2, on.getInvocations());
//        }

    }

    @Test
    public void xtest4p5AwsAutomaticWorkflowDoesNotUseCache() {
        // #. Create a new client that uses the AWS automatic workflow.
        // #. Ensure that a find operation does not add credentials to the cache.
        setOidcFile("test_user1");
        MongoCredential credential = MongoCredential.createOidcCredential(null)
                .withMechanismProperty(PROVIDER_NAME, "aws");
        ConnectionString connectionString = new ConnectionString(AWS_OIDC_URL);
        MongoClientSettings clientSettings = MongoClientSettings.builder()
                .credential(credential)
                .applyConnectionString(connectionString)
                .build();
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            performFind(mongoClient);
            // This ensures that the next find failure results in a file (rather than cache) read
            failCommand(391, 1, "find");
            setOidcFile("invalid_file");
            assertCause(NoSuchFileException.class, "invalid_file", () -> performFind(mongoClient));
        }
    }

    @Test
    public void test5SpeculativeAuthentication() {
        // #. We can only test the successful case, by verifying that saslStart is not called.
        // #. Create a client with a request callback that returns a valid token that will not expire soon.
        TestCallback onRequest = createCallback();
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, null);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Set a fail point for saslStart commands of the form:
            failCommand(18, 2 * 2, "saslStart");

            // #. Perform a find operation that succeeds.
            performFind(mongoClient);
            // #. Close the client.
            // #. Create a new client with the same properties without clearing the cache.
            // #. Set a fail point for saslStart commands.
            // #. Perform a find operation that succeeds.

            delayNextFind(); // cause both callbacks to be called
            executeAll(2, () -> performFind(mongoClient));
        }

        ///fail(); // TODO-OIDC
    }

    @Test
    public void xtest6p1ReauthenticationSucceeds() {
        // #. Create request and refresh callbacks that return valid credentials that will not expire soon.
        TestListener listener = new TestListener();
        TestCallback onRequest = createCallback().setEventListener(listener);
        TestCallback onRefresh = createCallback().setEventListener(listener);

        // #. Create a client with the callbacks and an event listener capable of listening for SASL commands.
        TestCommandListener commandListener = new TestCommandListener();
        commandListener.setEventStrings(listener);

        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh, null, commandListener);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {

            // #. Perform a find operation that succeeds.
            performFind(mongoClient);

            // #. Assert that the refresh callback has not been called.
            assertEquals(0, onRefresh.getInvocations());

            // #. Clear the listener state if possible.
            commandListener.reset();
            listener.clear();

            // #. Force a reauthenication using a failCommand
            failCommand(391, 1, "find");

            // #. Perform another find operation that succeeds.
            performFind(mongoClient);

            // #. Assert that the refresh callback has been called once, if possible.
            assertEquals(1, onRefresh.getInvocations());

            // #. Assert that the ordering of command started events is: find, find.
            // #. Assert that the ordering of command succeeded events is: find.
            // #. Assert that a find operation failed once during the command execution.
            assertEquals(Arrays.asList(
                    "find started",
                    "find failed",
                    "saslStart started",
                    "saslStart succeeded",
                    "find started",
                    "find succeeded"
            ), listener.getEventStrings());
        }
    }

    @Test
    public void testFullReath() {
        ConcurrentLinkedQueue<String> tokens = tokenQueue(
                "test_user1", // read during initial population
                "test_user1_1", // read when first thread clears cache
                "test_user1_expires", // read during onRefresh
                "test_user1_2", // read during onRequest
                "invalid");
        TestListener events = new TestListener() {
            public void add(final String s) {
                String message = new Date() + " -- " +
                        Thread.currentThread().getName() + " -- " +
                        s;
                System.out.println(message);
                events.add(message);
            }
        };
        TestCallback onRequest = new TestCallback()
                .setPathSupplier(() -> {
                    String remove = tokens.remove();
                    events.add("request pulled token: " + remove);
                    return remove;
                })
                .setEventListener(events);
        TestCallback onRefresh = new TestCallback()
                .setPathSupplier(() -> {
                    String remove = tokens.remove();
                    events.add("refresh pulled token: " + remove);
                    return remove;
                })
                .setEventListener(events);
        TestCommandListener commandListener = new TestCommandListener();
        commandListener.setEventStrings(events);

        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh, null, commandListener);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // Populate the cache, authenticate both connections
            delayNextFind();
            executeAll(2, () -> performFind(mongoClient));
            assertEquals(1, onRequest.getInvocations());
            assertEquals(0, onRefresh.getInvocations());

            events.add("----CLEAR----");
            events.clear();

            // Now we need a thread to arrive at AUTHLOCK after a failed find,
            // but the cache must contain a new credential.
            // The first thread performs a failing-find that takes a long time.
            // Then, the second thread starts, and immediately fails its find,
            // and passes through AUTHLOCK to populate the cache.
            executeAll(
                    () -> {
                        events.add("###cachekiller started");
                        failCommand(391, 1, "find");
                        performFind(mongoClient);
                        events.add("###cachekiller finished");
                    },
                    () -> {
                        sleep(500); // TODO-OIDC less time
                        events.add("----CLEAR222222----");
                        events.clear();
                        events.add("###retrier started");

                        failCommand(391, 1, "find");
                        performFind(mongoClient);

                        events.add("###retrier finished");
                    });

            System.out.println("----AA----");
            events.getEventStrings().forEach(e -> System.out.println("##  " + e));

            System.out.println("----BB----");
//            assertEquals(Arrays.asList(
//                    "find started",
//                    "find failed",
//                    "saslStart started",
//                    "saslStart succeeded",
//                    "onRequest invoked",
//                    "saslContinue started",
//                    "saslContinue succeeded",
//                    "find started",
//                    "find succeeded"
//            ), events);

        }
    }

    @NotNull
    private ConcurrentLinkedQueue<String> tokenQueue(final String... queue) {
        return Stream
                .of(queue)
                .map(v -> TOKEN_DIRECTORY + v)
                .collect(Collectors.toCollection(ConcurrentLinkedQueue::new));
    }

//    private void performSleepingMapReduce(final MongoClient client, final int ms) {
//        client
//                .getDatabase("test")
//                .getCollection("test")
//                .mapReduce(
//                        "function () { emit('a', this.a) }",
//                        "function (k, v) { return sleep(" + ms + ") || Array.sum(v)}")
//                .first();
//    }


    // TODO-OIDC reauth sasl events must not be logged

    @Test
    public void xtest6p2ReauthenticationRetriesAndSucceedsWithCache() {
        // #. Create request and refresh callbacks that return valid credentials that will not expire soon.
        TestCallback onRequest = createCallback();
        TestCallback onRefresh = createCallback();
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Perform a find operation that succeeds.
            performFind(mongoClient);
            // #. Force a reauthenication using a failCommand
            failCommand(391, 2, "find", "saslStart");
            // #. Perform a find operation that succeeds.
            performFind(mongoClient);
        }
    }


    @Test
    public void cannotImplement_test6p3RetriesAndFailsWithNoCache() {
        // TODO-OIDC speculative auth
        fail();
    }

    @Test
    public void xtest6p4SeparateConnectionsAvoidExtraCallbackCalls() {
        ConcurrentLinkedQueue<String> tokens = tokenQueue(
                "test_user1",
                "test_user1_1");
        Supplier<String> stringSupplier = () -> tokens.remove();

        TestCallback onRequest = createCallback().setPathSupplier(stringSupplier);
        TestCallback onRefresh = createCallback().setPathSupplier(stringSupplier);
        MongoClientSettings clientSettings = createSettings(OIDC_URL, onRequest, onRefresh);
        try (MongoClient mongoClient = createMongoClient(clientSettings)) {
            // #. Peform a find operation on each ... that succeeds.
            delayNextFind();
            executeAll(2, () -> performFind(mongoClient));
            // #. Ensure that the request callback has been called once and the refresh callback has not been called.
            assertEquals(1, onRequest.getInvocations());
            assertEquals(0, onRefresh.getInvocations());

            failCommand(391, 2, "find");
            executeAll(2, () -> performFind(mongoClient));

            // #. Ensure that the request callback has been called once and the refresh callback has been called once.
            assertEquals(1, onRequest.getInvocations());
            assertEquals(1, onRefresh.getInvocations());
        }
    }

    public MongoClientSettings createSettings(
            final String connectionString,
            @Nullable final RequestCallback onRequest,
            @Nullable final RefreshCallback onRefresh) {
        return createSettings(connectionString, onRequest, onRefresh, null, null);
    }

    private MongoClientSettings createSettings(
            final String connectionString,
            @Nullable final RequestCallback onRequest,
            @Nullable final RefreshCallback onRefresh,
            @Nullable final List<String> allowedHosts,
            @Nullable final CommandListener commandListener) {
        ConnectionString cs = new ConnectionString(connectionString);
        MongoCredential credential = cs.getCredential()
                .withMechanismProperty(REQUEST_TOKEN_CALLBACK, onRequest)
                .withMechanismProperty(REFRESH_TOKEN_CALLBACK, onRefresh)
                .withMechanismProperty(ALLOWED_HOSTS, allowedHosts);
        MongoClientSettings.Builder builder = MongoClientSettings.builder()
                .applyConnectionString(cs)
                .credential(credential);
        if (commandListener != null) {
            builder.addCommandListener(commandListener);
        }
        return builder.build();
    }

    private void performFind(final MongoClientSettings settings) {
        try (MongoClient mongoClient = createMongoClient(settings)) {
            performFind(mongoClient);
        }
    }

    private <T extends Throwable> void performFind(
            final MongoClientSettings settings,
            final Class<T> expectedExceptionOrCause,
            final String expectedMessage) {

        try (MongoClient mongoClient = createMongoClient(settings)) {
            assertCause(expectedExceptionOrCause, expectedMessage, () -> performFind(mongoClient));
        }
    }

    private static <T extends Throwable> void assertCause(
            final Class<T> expectedCause, final String expectedMessageFragment, final Executable e) {
        Throwable actualException = assertThrows(Throwable.class, e);

        assertCause(expectedCause, expectedMessageFragment, actualException);
    }

    private static <T extends Throwable> void assertCause(
            final Class<T> expectedCause, final String expectedMessageFragment, final Throwable actualException) {
        Throwable cause = actualException;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        if (!expectedCause.isInstance(cause)) {
            throw new AssertionFailedError("Unexpected cause", actualException);
        }
        if (!cause.getMessage().contains(expectedMessageFragment)) {
            throw new AssertionFailedError("Unexpected message", actualException);
        }
    }

    private void performFind(final MongoClient mongoClient) {
        mongoClient
                .getDatabase("test")
                .getCollection("test")
                .find()
                .first();
    }



    private void delayThenFailCommand(final String command, final int times, final int ms, final int code) {
        try (MongoClient client = createMongoClient(createSettings(AWS_OIDC_URL, null, null))) {
            BsonDocument configureFailPoint = new BsonDocument()
                    .append("configureFailPoint", new BsonString("failCommand"))
                    .append("mode", new BsonDocument()
                            .append("times", new BsonInt32(times)))
                    .append("data", new BsonDocument()
                            .append("failCommands", new BsonArray(Arrays.asList(new BsonString(command))))
                            .append("errorCode", new BsonInt32(code))
                            .append("blockConnection", BsonBoolean.valueOf(true))
                            .append("blockTimeMS", new BsonInt32(ms))
                    );
                        // .append("appName", new BsonString(appName)) TODO-OIDC
            client.getDatabase("admin").runCommand(configureFailPoint);
        }
    }

    private void delayCommand(final MongoClient mongoClient, final String command, final int ms) {
        BsonDocument failPointDocument = new BsonDocument("configureFailPoint", new BsonString("failCommand"))
                .append("mode", new BsonDocument("times", new BsonInt32(1)))
                .append("data", new BsonDocument()
                        .append("failCommands", new BsonArray(asList(new BsonString(command))))
                        .append("blockConnection", new BsonBoolean(true))
                        .append("blockTimeMS", new BsonInt32(ms)));
        mongoClient.getDatabase("admin").runCommand(failPointDocument);
    }

    protected void delayNextFind() {
        try (MongoClient client = createMongoClient(createSettings(AWS_OIDC_URL, null, null))) {
            delayCommand(client, "find", 100);
        }
    }

    protected void failCommand(final int code, final int times, final String... commands) {
        try (MongoClient mongoClient = createMongoClient(createSettings(
                AWS_OIDC_URL, null, null))) {
            List<BsonString> list = Arrays.stream(commands).map(c -> new BsonString(c)).collect(Collectors.toList());
            BsonDocument failPointDocument = new BsonDocument("configureFailPoint", new BsonString("failCommand"))
                    .append("mode", new BsonDocument("times", new BsonInt32(times)))
                    .append("data", new BsonDocument()
                            .append("failCommands", new BsonArray(list))
                            .append("errorCode", new BsonInt32(code)));
            mongoClient.getDatabase("admin").runCommand(failPointDocument);
        }
        // TODO-OIDC the driver MUST either use a unique appName or explicitly remove the failCommand after the test to prevent leakage.
    }

    public static class TestCallback implements RequestCallback, RefreshCallback {
        private final AtomicInteger invocations = new AtomicInteger();
        @Nullable
        private final Integer expiresInSeconds;
        @Nullable
        private final Integer delayInMilliseconds;
        @Nullable
        private final AtomicInteger concurrentTracker;
        @Nullable
        private final TestListener testListener;
        @Nullable
        private final Supplier<String> pathSupplier;

        public TestCallback() {
            this(60 * 60, null, null, null, null);
        }

        public TestCallback(
                @Nullable final Integer expiresInSeconds,
                @Nullable final Integer delayInMilliseconds,
                @Nullable final AtomicInteger concurrentTracker,
                @Nullable final TestListener testListener,
                @Nullable final Supplier<String> pathSupplier) {
            this.expiresInSeconds = expiresInSeconds;
            this.delayInMilliseconds = delayInMilliseconds;
            this.concurrentTracker = concurrentTracker;
            this.testListener = testListener;
            this.pathSupplier = pathSupplier;
        }

        public int getInvocations() {
            return invocations.get();
        }

        @Override
        public IdPServerResponse onRequest(
                @Nullable final String principalName,
                final MongoCredential.IdpServerInfo serverInfo,
                final int timeoutSeconds) {
            if (testListener != null) {
                testListener.add("onRequest invoked");
            }
            return callback();
        }

        @NotNull
        private IdPServerResponse callback() {
            if (concurrentTracker != null) {
                if (concurrentTracker.get() > 0) {
                    throw new RuntimeException("Callbacks should not be invoked by multiple threads.");
                }
                concurrentTracker.incrementAndGet();
            }
            try {
                invocations.incrementAndGet();
                String path = pathSupplier == null
                        ? getenv(AWS_WEB_IDENTITY_TOKEN_FILE)
                        : pathSupplier.get();
                String accessToken;
                try {
                    simulateDelay();
                    accessToken = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
                String refreshToken = "refreshToken";
                System.out.println("READ ACCESS TOKEN: " + path + " -- " + accessToken.hashCode());
                return new IdPServerResponse(
                        accessToken,
                        expiresInSeconds,
                        refreshToken);
            } finally {
                if (concurrentTracker != null) {
                    concurrentTracker.decrementAndGet();
                }
            }
        }

        private void simulateDelay() throws InterruptedException {
            if (delayInMilliseconds != null) {
                Thread.sleep(delayInMilliseconds);
            }
        }

        @Override
        public IdPServerResponse onRefresh(
                @Nullable final String principalName,
                final MongoCredential.IdpServerInfo serverInfo,
                @Nullable final String refreshToken, // test against null
                final int timeoutSeconds) {
            if (refreshToken == null) {
                throw new IllegalArgumentException("refreshToken was null");
            }
            return callback();
        }

        public TestCallback setExpiresInSeconds(final Integer expiresInSeconds) {
            return new TestCallback(
                    expiresInSeconds,
                    this.delayInMilliseconds,
                    this.concurrentTracker,
                    this.testListener,
                    this.pathSupplier);
        }

        public TestCallback setDelayMs(final int milliseconds) {
            return new TestCallback(
                    this.expiresInSeconds,
                    milliseconds,
                    this.concurrentTracker,
                    this.testListener,
                    this.pathSupplier);
        }

        public TestCallback setConcurrentTracker(final AtomicInteger c) {
            return new TestCallback(
                    this.expiresInSeconds,
                    this.delayInMilliseconds,
                    c,
                    this.testListener,
                    this.pathSupplier);
        }

        public TestCallback setEventListener(final TestListener testListener) {
            return new TestCallback(
                    this.expiresInSeconds,
                    this.delayInMilliseconds,
                    this.concurrentTracker,
                    testListener,
                    this.pathSupplier);
        }

        public TestCallback setPathSupplier(final Supplier<String> pathSupplier) {
            return new TestCallback(
                    this.expiresInSeconds,
                    this.delayInMilliseconds,
                    this.concurrentTracker,
                    this.testListener,
                    pathSupplier);
        }
    }

    public TestCallback createCallback() {
        return new TestCallback();
    }

    @NotNull
    public TestCallback createExpiredCallback() {
        return createCallback().setExpiresInSeconds(60);
    }

}
