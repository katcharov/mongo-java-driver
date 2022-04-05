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
package com.mongodb.client.model.search;

import org.bson.BsonDocument;
import org.junit.jupiter.api.Test;

import static com.mongodb.client.model.search.SearchFacet.combineToBsonDocument;
import static com.mongodb.client.model.search.SearchFacet.numberFacet;
import static com.mongodb.client.model.search.SearchFacet.stringFacet;
import static com.mongodb.client.model.search.SearchOperator.exists;
import static com.mongodb.client.model.search.SearchPath.fieldPath;
import static java.util.Arrays.asList;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SearchCollectorTest {
    @Test
    void of() {
        assertAll(
                () -> assertEquals(
                        docExampleCustom(),
                        docExamplePredefined()
                                .toBsonDocument()
                ),
                () -> assertThrows(IllegalArgumentException.class, () ->
                        new BsonDocument("facet",
                                new BsonDocument("operator", exists(
                                        fieldPath("fieldName")).toBsonDocument())
                                        .append("facets", combineToBsonDocument(asList(
                                                stringFacet(
                                                        "duplicateFacetName",
                                                        fieldPath("stringFieldName")),
                                                numberFacet(
                                                        "duplicateFacetName",
                                                        fieldPath("numberFieldName"),
                                                        asList(10, 20, 30))))))
                )
        );
        assertEquals(
                docExamplePredefined()
                        .toBsonDocument(),
                SearchCollector.of(docExampleCustom())
                        .toBsonDocument()
        );
    }

    @Test
    void facet() {
        assertAll(
                () -> assertThrows(IllegalArgumentException.class, () ->
                        SearchCollector.facet(
                                exists(
                                        fieldPath("fieldName")),
                                asList(
                                        stringFacet(
                                                "duplicateFacetName",
                                                fieldPath("stringFieldName")),
                                        numberFacet(
                                                "duplicateFacetName",
                                                fieldPath("numberFieldName"),
                                                asList(10, 20, 30))))
                ),
                () -> assertEquals(
                        docExampleCustom(),
                        docExamplePredefined()
                                .toBsonDocument()
                )
        );
    }

    private static SearchCollector docExamplePredefined() {
        return SearchCollector.facet(
                exists(
                        fieldPath("fieldName")),
                asList(
                        stringFacet(
                                "stringFacetName",
                                fieldPath("stringFieldName")),
                        numberFacet(
                                "numberFacetName",
                                fieldPath("numberFieldName"),
                                asList(10, 20, 30))));
    }

    private static BsonDocument docExampleCustom() {
        return new BsonDocument("facet",
                new BsonDocument("operator", exists(
                        fieldPath("fieldName")).toBsonDocument())
                        .append("facets", combineToBsonDocument(asList(
                                stringFacet(
                                        "stringFacetName",
                                        fieldPath("stringFieldName")),
                                numberFacet(
                                        "numberFacetName",
                                        fieldPath("numberFieldName"),
                                        asList(10, 20, 30))))));
    }
}
