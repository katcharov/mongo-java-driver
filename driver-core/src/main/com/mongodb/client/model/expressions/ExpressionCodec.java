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

package com.mongodb.client.model.expressions;

import com.mongodb.annotations.Immutable;
import com.mongodb.client.model.expressions.Expressions;
import org.bson.BsonReader;
import org.bson.BsonValue;
import org.bson.BsonWriter;
import org.bson.codecs.BsonValueCodecProvider;
import org.bson.codecs.Codec;
import org.bson.codecs.DecoderContext;
import org.bson.codecs.EncoderContext;
import org.bson.codecs.configuration.CodecRegistry;

import static org.bson.codecs.configuration.CodecRegistries.fromProviders;

@Immutable
public final class ExpressionCodec implements Codec<Expressions.GenEx> {
    private static final CodecRegistry DEFAULT_REGISTRY = fromProviders(new BsonValueCodecProvider());

    private final CodecRegistry codecRegistry;

    /**
     * Creates a new instance initialised with the default codec registry.
     *
     */
    public ExpressionCodec() {
        this(DEFAULT_REGISTRY);
    }

    /**
     * Creates a new instance initialised with the given codec registry.
     *
     * @param codecRegistry the {@code CodecRegistry} to use to look up the codecs for encoding and decoding to/from BSON
     */
    public ExpressionCodec(final CodecRegistry codecRegistry) {
        this.codecRegistry = codecRegistry;
    }

    @Override
    public Expressions.GenEx decode(final BsonReader reader, final DecoderContext decoderContext) {
        throw new UnsupportedOperationException("Decoding to an expression is not supported");
    }

    @Override
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void encode(final BsonWriter writer, final Expressions.GenEx value, final EncoderContext encoderContext) {
        // TODO fix cast? at least the check has to be earlier
        BsonValue bsonValue = ((Expressions.ExImpl) value).toBsonValue(codecRegistry);
        Codec codec = codecRegistry.get(bsonValue.getClass());
        codec.encode(writer, bsonValue, encoderContext);
    }

    @Override
    public Class<Expressions.GenEx> getEncoderClass() {
        return Expressions.GenEx.class;
    }
}
