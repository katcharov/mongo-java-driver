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

import com.mongodb.MongoClientSettings;
import com.mongodb.ReadConcern;
import com.mongodb.WriteConcern;
import com.mongodb.client.model.SearchIndexModel;
import com.mongodb.client.model.SearchIndexType;
import com.mongodb.event.CommandListener;
import com.mongodb.event.CommandStartedEvent;
import org.bson.BsonDocument;
import org.bson.BsonSerializationException;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static com.mongodb.ClusterFixture.serverVersionAtLeast;
import static com.mongodb.assertions.Assertions.assertFalse;
import static com.mongodb.client.Fixture.getMongoClientSettings;
import static com.mongodb.client.Fixture.getMongoClientSettingsBuilder;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * See <a href="https://github.com/mongodb/specifications/blob/master/source/index-management/tests/README.rst#search-index-management-helpers">Search Index Management Tests</a>
 */
public abstract class AbstractAtlasSearchIndexManagementProseTest {
    /**
     * The maximum number of attempts for waiting for changes or completion.
     * If this many attempts are made without success, the test will be marked as failed.
     */
    private static final int MAX_WAIT_ATTEMPTS = 70;

    /**
     * The duration in seconds to wait between each attempt when waiting for changes or completion.
     */
    private static final int WAIT_INTERVAL_SECONDS = 5;

    private static final String TEST_SEARCH_INDEX_NAME_1 = "test-search-index";
    private static final String TEST_SEARCH_INDEX_NAME_2 = "test-search-index-2";
    private static final Document MAPPINGS_DYNAMIC_FALSE = Document.parse(
                      "{"
                    + "  mappings: { dynamic: false }"
                    + "}");
    private static final Document MAPPINGS_DYNAMIC_TRUE = Document.parse(
                      "{"
                    + "  mappings: { dynamic: true }"
                    + "}");
    private MongoClient client = createMongoClient(getMongoClientSettings());
    private MongoDatabase db;
    private MongoCollection<Document> collection;

    protected abstract MongoClient createMongoClient(MongoClientSettings settings);

    protected AbstractAtlasSearchIndexManagementProseTest() {
       Assumptions.assumeTrue(serverVersionAtLeast(6, 0));
       Assumptions.assumeTrue(hasAtlasSearchIndexHelperEnabled(), "Atlas Search Index tests are disabled");
    }

    private static boolean hasAtlasSearchIndexHelperEnabled() {
        return Boolean.parseBoolean(System.getProperty("org.mongodb.test.atlas.search.index.helpers"));
    }

    @BeforeEach
    public void setUp() {
        MongoClientSettings mongoClientSettings = getMongoClientSettingsBuilder()
                .writeConcern(WriteConcern.MAJORITY)
                .readConcern(ReadConcern.MAJORITY)
                .addCommandListener(new CommandListener() {
                    @Override
                    public void commandStarted(final CommandStartedEvent event) {
                   /* This test case examines scenarios where the write or read concern is not forwarded to the server
                    for any Atlas Index Search commands. If a write or read concern is included in the command,
                    the server will return an error. */
                        if (isSearchIndexCommand(event)) {
                            BsonDocument command = event.getCommand();
                            assertFalse(command.containsKey("writeConcern"));
                            assertFalse(command.containsKey("readConcern"));
                        }
                    }

                    private boolean isSearchIndexCommand(final CommandStartedEvent event) {
                       return event.getCommand().toJson().contains("SearchIndex");
                    }
                })
                .build();

        client = createMongoClient(mongoClientSettings);
        db = client.getDatabase("test");

        String collectionName = UUID.randomUUID().toString();
        db.createCollection(collectionName);
        collection = db.getCollection(collectionName);
    }

    @AfterEach
    void cleanUp() {
        try {
            collection.drop();
            db.drop();
        } finally {
            client.close();
        }
    }

    @Test
    @DisplayName("Case 1: Driver can successfully create and list search indexes")
    public void shouldCreateAndListSearchIndexes() throws InterruptedException {
        //given
        SearchIndexModel searchIndexModel = new SearchIndexModel(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE);

        //when
        String createdSearchIndexName = collection.createSearchIndex(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE);

        //then
        Assertions.assertEquals(TEST_SEARCH_INDEX_NAME_1, createdSearchIndexName);
        assertIndexesChanges(isQueryable(), searchIndexModel);
    }

    @Test
    @DisplayName("Case 2: Driver can successfully create multiple indexes in batch")
    public void shouldCreateMultipleIndexesInBatch() throws InterruptedException {
        //given
        SearchIndexModel searchIndexModel1 = new SearchIndexModel(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE);
        SearchIndexModel searchIndexModel2 = new SearchIndexModel(TEST_SEARCH_INDEX_NAME_2, MAPPINGS_DYNAMIC_FALSE);

        //when
        List<String> searchIndexes = collection.createSearchIndexes(Arrays.asList(searchIndexModel1, searchIndexModel2));

        //then
        assertThat(searchIndexes, contains(TEST_SEARCH_INDEX_NAME_1, TEST_SEARCH_INDEX_NAME_2));
        assertIndexesChanges(isQueryable(), searchIndexModel1, searchIndexModel2);
    }

    @Test
    @DisplayName("Case 3: Driver can successfully drop search indexes")
    public void shouldDropSearchIndex() throws InterruptedException {
        //given
        String createdSearchIndexName = collection.createSearchIndex(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE);
        Assertions.assertEquals(TEST_SEARCH_INDEX_NAME_1, createdSearchIndexName);
        awaitIndexChanges(isQueryable(), new SearchIndexModel(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE));

        //when
        collection.dropSearchIndex(TEST_SEARCH_INDEX_NAME_1);

        //then
        assertIndexDeleted();
    }

    @Test
    @DisplayName("Case 4: Driver can update a search index")
    public void shouldUpdateSearchIndex() throws InterruptedException {
        //given
        String createdSearchIndexName = collection.createSearchIndex(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE);
        Assertions.assertEquals(TEST_SEARCH_INDEX_NAME_1, createdSearchIndexName);
        awaitIndexChanges(isQueryable(), new SearchIndexModel(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_FALSE));

        //when
        collection.updateSearchIndex(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_TRUE);

        //then
        assertIndexesChanges(isReady().and(isQueryable()), new SearchIndexModel(TEST_SEARCH_INDEX_NAME_1, MAPPINGS_DYNAMIC_TRUE));
    }

    @Test
    @DisplayName("Case 5: dropSearchIndex suppresses namespace not found errors")
    public void shouldSuppressNamespaceErrorWhenDroppingIndexWithoutCollection() {
        //given
        collection.drop();

        //when
        collection.dropSearchIndex("not existent index");
    }

    @Test
    @DisplayName("Case 7: Driver can successfully handle search index types when creating indexes")
    public void shouldHandleSearchIndexTypes() {
        // 01. Create a collection with the "create" command using a randomly
        // generated name (referred to as `coll0`).

        // TODO: fill in test
        // 02. Create a new search index on `coll0` with the `createSearchIndex`
        // helper. Use the following definition:
        String result1 = collection.createSearchIndex(
                "test-search-index-case7-implicit",
                MAPPINGS_DYNAMIC_FALSE);

        // 03. Assert that the command returns the name of the index:
        assertEquals("test-search-index-case7-implicit", result1);

        // 04. Run `coll0.listSearchIndexes('test-search-index-case7-implicit')`
        // repeatedly every 5 seconds until the following condition is satisfied
        // and store the value in a variable `index1`:
        // - An index with the `name` of `test-search-index-case7-implicit` is
        // present and the index has a field `queryable` with a value of `true`.

        // 05. Assert that `index1` has a property `type` whose value is `search`.


        // 06. Create a new search index on `coll0` with the `createSearchIndex`
        // helper. Use the following definition:
        String result2 = collection.createSearchIndex(
                "test-search-index-case7-explicit",
                MAPPINGS_DYNAMIC_FALSE,
                SearchIndexType.SEARCH);

        // 07. Assert that the command returns the name of the index:
        assertEquals("test-search-index-case7-explicit", result2);

        // 08. Run `coll0.listSearchIndexes('test-search-index-case7-explicit')`
        // repeatedly every 5 seconds until the following condition is satisfied
        // and store the value in a variable `index2`:
        // - An index with the `name` of `test-search-index-case7-explicit` is
        // present and the index has a field `queryable` with a value of `true`.

        // 09. Assert that `index2` has a property `type` whose value is `search`.


        // 10. Create a new vector search index on `coll0` with the
        // `createSearchIndex` helper. Use the following definition:
        String result3 = collection.createSearchIndex(
                "test-search-index-case7-vector",
                Document.parse("{\n"
                        + "    fields: [\n"
                        + "        {\n"
                        + "            type: 'vector',\n"
                        + "            path: 'plot_embedding',\n"
                        + "            numDimensions: 1536,\n"
                        + "            similarity: 'euclidean',\n"
                        + "        },\n"
                        + "    ]\n"
                        + "}"),
                SearchIndexType.VECTOR_SEARCH);

        // 11. Assert that the command returns the name of the index:
        assertEquals("test-search-index-case7-vector", result3);

        // 12. Run `coll0.listSearchIndexes('test-search-index-case7-vector')`
        // repeatedly every 5 seconds until the following condition is satisfied
        // and store the value in a variable `index3`:
        // - An index with the `name` of `test-search-index-case7-vector` is
        // present and the index has a field `queryable` with a value of `true`.

        // 13. Assert that `index3` has a property `type` whose value is `vectorSearch`.
    }

    @Test
    @DisplayName("Case 8: Driver requires explicit type to create a vector search index")
    public void shouldRequireExpicitTypeToCreateVectorSearchIndex() {
        // 1. Create a collection with the "create" command using a randomly
        // generated name (referred to as `coll0`).

        // 2. Create a new vector search index on `coll0` with the
        // `createSearchIndex` helper. Use the following definition:

        Bson definition = Document.parse("{\n"
                + "    name: 'test-search-index-case8-error',\n"
                + "    definition: {\n"
                + "      fields: [\n"
                + "         {\n"
                + "             type: 'vector',\n"
                + "             path: 'plot_embedding',\n"
                + "             numDimensions: 1536,\n"
                + "             similarity: 'euclidean',\n"
                + "         },\n"
                + "      ]\n"
                + "    }\n"
                + "  }");

        // 3. Assert that the command throws an exception containing the string
        // "Attribute mappings missing" due to the `mappings` field missing.
        // TODO: update exception class
        assertThrows(BsonSerializationException.class, () -> {
            collection.createSearchIndex(definition);
        }, "Attribute mappings missing");
    }

    private void assertIndexDeleted() throws InterruptedException {
        int attempts = MAX_WAIT_ATTEMPTS;
        while (collection.listSearchIndexes().first() != null && checkAttempt(attempts--)) {
            await();
        }
    }

    private void assertIndexesChanges(final Predicate<Document> indexStatus, final SearchIndexModel... searchIndexModels)
            throws InterruptedException {

        Map<String, Document> createdIndexes = awaitIndexChanges(indexStatus, searchIndexModels);
        Assertions.assertEquals(searchIndexModels.length, createdIndexes.size());

        for (SearchIndexModel searchIndexModel : searchIndexModels) {
            Bson mappings = searchIndexModel.getDefinition();
            String searchIndexName = searchIndexModel.getName();

            Document createdIndex = createdIndexes.get(searchIndexName);
            Assertions.assertNotNull(createdIndex);
            Assertions.assertEquals(createdIndex.get("latestDefinition"), mappings);
        }
    }


    private Map<String, Document> awaitIndexChanges(final Predicate<Document> indexStatus, final SearchIndexModel... searchIndexModels)
            throws InterruptedException {
        int attempts = MAX_WAIT_ATTEMPTS;
        while (checkAttempt(attempts--)) {
            Map<String, Document> existingIndexes = StreamSupport.stream(collection.listSearchIndexes().spliterator(), false)
                    .filter(indexStatus)
                    .collect(Collectors.toMap(document -> document.getString("name"), Function.identity()));

            if (checkNames(existingIndexes, searchIndexModels)) {
                return existingIndexes;
            }
            await();
        }
        return Assertions.fail();
    }

    private Predicate<Document> isQueryable() {
        return document -> document.getBoolean("queryable");
    }

    private Predicate<Document> isReady() {
        return document -> "READY".equals(document.getString("status"));
    }


    private boolean checkAttempt(final int attempt) {
        Assertions.assertFalse(attempt <= 0, "Exceeded maximum attempts waiting for Search Index changes in Atlas cluster");
        return true;
    }

    private static void await() throws InterruptedException {
        TimeUnit.SECONDS.sleep(WAIT_INTERVAL_SECONDS);
    }

    private static boolean checkNames(final Map<String, Document> existingIndexes, final SearchIndexModel... searchIndexModels) {
        for (SearchIndexModel searchIndexModel : searchIndexModels) {
            String searchIndexName = searchIndexModel.getName();
            if (!existingIndexes.containsKey(searchIndexName)) {
                return false;
            }

        }
        return true;
    }
}
