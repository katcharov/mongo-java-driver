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
package com.mongodb.client.model;

import com.mongodb.annotations.Evolving;
import org.bson.BsonDocument;
import org.bson.BsonValue;

/**
 * An interface for types that are able to render themselves into a {@link BsonField}.
 */
@Evolving
public interface ToBsonField {
    /**
     * Renders into {@link BsonField}.
     *
     * @return A {@link BsonField} representation.
     */
    BsonField toBsonField();

    /**
     * {@linkplain BsonDocument#append(String, BsonValue) Appends} the result of {@link #toBsonField()} to {@code doc}.
     * @param doc The document to append to.
     * @return {@code doc}.
     */
    // VAKOTODO Hide from users?
    default BsonDocument appendTo(final BsonDocument doc) {
        final BsonField bsonField = toBsonField();
        return doc.append(bsonField.getName(), bsonField.getValue().toBsonDocument());
    }
}
