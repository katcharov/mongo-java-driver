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

import org.bson.BsonDocument;
import org.bson.BsonValue;
import org.bson.Document;
import org.bson.codecs.configuration.CodecRegistry;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;

public final class Expressions {

    // TODO class instead of interface? to close implementations
    public interface GenEx { // TODO <T extends GenEx> ?
        //BsonValue toBsonValue(CodecRegistry codecRegistry); // single method interface takes over functions

        // TODO is this type of casting needed?
        default NumEx asNum() {
            return (NumEx) this;
        }

        default BoolEx eq(GenEx eq) {
            return Expressions.eq(this, eq);
        }

        default BoolEx eq(Object eq) { // TODO too permissive?
            return this.eq(new ExImpl(eq));
        }

        default GenEx ifNull(GenEx of) {
            return Expressions.ifNull(this, of);
        }
    }

    public interface NumEx extends GenEx {
        default NumEx add(NumEx add) {
            return Expressions.add(add);
        }
    }
    public interface IntEx extends NumEx {
        default IntEx add(IntEx add) {
            return Expressions.add(this, add);
        }
        default IntEx add(int add) {
            return this.add(of(add));
        }
    }
    public interface DateEx extends GenEx {
        default GenEx year() {
            return Expressions.year(this);
        }
    }
    public interface BoolEx extends GenEx {

        default <T extends GenEx> T cond(final T thenExp, final T elseExp) {
            return Expressions.cond(this, thenExp, elseExp);
        }
    }
    public interface StrEx extends GenEx {
    }
    public interface ArrEx<T extends GenEx> extends GenEx {
        default IntEx size() {
            return Expressions.size(this);
        }

        default T arrayElemAt(int i) {
            return Expressions.arrayElemAt(this, i);
        }

        default ArrEx<T> map(T e) {
            // TODO
            return Expressions.map(this, e);
        }
        default <R extends GenEx> ArrEx<R> map(Function<T, ? extends R> mapper) {
            return Expressions.map(this, mapper.apply( (T) variableThis() ));
        }
        default T reduce(T initialValue, BiFunction<T, T, ? extends T> mapper) {
            T value = Expressions.reduce(this, initialValue,
                    mapper.apply((T) variableThis(), (T) variable("value")));
            return value;
        }
    }
    public interface ObjEx extends GenEx {
    }

    static class ExImpl implements NumEx, IntEx, BoolEx, StrEx, GenEx, ObjEx, DateEx {
        private final Object o;

        ExImpl(final Object o) {
            this.o = o;
        }

        public static ExImpl doc(final String name, final Object o) {
            return new ExImpl(new Document(name, o));
        }

        //@Override
        public BsonValue toBsonValue(final CodecRegistry codecRegistry) {
            // TODO
            return new Document("val", o).toBsonDocument(BsonDocument.class, codecRegistry).get("val");
        }
    }
    static class ExArrImpl<T extends GenEx> extends ExImpl implements ArrEx<T> {
        ExArrImpl(final Object o) {
            super(o);
        }

        public static ExArrImpl doc(final String name, final Object o) {
            return new ExArrImpl(new Document(name, o));
        }
    }



    public static Object bind(final String name, final NumEx exp) {
        return null;
    }

    public static NumEx refNum(final String refNum) {
        return null;
    }

//    public static <T extends GenEx> T let(final T exp, final Object... exps) {
//        return null;
//    }

    public static <
            T extends GenEx,
            TV1 extends GenEx> T let(
            final TV1 var1,
            final Function<TV1, T> ex) {
        Document vars = new Document();
        vars.put("var1", var1);
        Document d = new Document();
        d.put("vars", vars);
        d.put("in", ex.apply((TV1) variable("var1")));
        return (T) ExImpl.doc("$let", d);
    }
    public static <
            T extends GenEx,
            TV1 extends GenEx,
            TV2 extends GenEx> T let(
            final TV1 var1,
            final TV2 var2,
            final BiFunction<TV1, TV2, T> ex) {
        Document vars = new Document();
        vars.put("var1", var1);
        vars.put("var2", var2);
        Document d = new Document();
        d.put("vars", vars);
        d.put("in", ex.apply((TV1) variable("var1"), (TV2) variable("var2")));
        return (T) ExImpl.doc("$let", d);
    }




    public static <T extends GenEx> T to(final GenEx q, final Class<T> c) {
        return null;
    }

    public static GenEx field(final String field) {
        // TODO escape?
        return new ExImpl("$" + field);
    }
    public static GenEx variable(final String variable) {
        // TODO escape?
        return new ExImpl("$$" + variable);
    }
    public static StrEx variableStr(final String variable) {
        // TODO escape?
        return new ExImpl("$$" + variable);
    }
    public static IntEx variableInt(final String variable) {
        // TODO escape?
        return new ExImpl("$$" + variable);
    }
    public static <T extends GenEx> ArrEx<T> variableArr(final String variable) {
        // TODO escape?
        return new ExArrImpl("$$" + variable);
    }
    public static GenEx variableThis() {
        return new ExImpl("$$this");
    }
    public static NumEx variableThisNum() {
        return new ExImpl("$$this");
    }
//    public static <T> ArrExp<T> fieldArr(final String f, final Class<T> c) {
//        return null;
//    }
    public static ArrEx<GenEx> fieldArr(final String fieldArr) {
        return fieldArr(fieldArr, GenEx.class);
    }
    public static <T extends GenEx> ArrEx<T> fieldArr(final String fieldArr, final Class<T> c) {
        if (fieldArr.startsWith("$")) {
            throw new IllegalArgumentException("Fields must not start with $. For variables, use "); // TODO
        }
        return new ExArrImpl<T>("$" + fieldArr);
    }
    public static ObjEx fieldObj(final String field) {
        return (ObjEx) field(field);
    }
    public static NumEx fieldNum(final String field) {
        return (NumEx) field(field);
    }
    public static IntEx fieldInt(final String field) {
        return (IntEx) field(field);
    }
    public static DateEx fieldDate(final String field) {
        return (DateEx) field(field);
    }
    public static BoolEx fieldBool(final String field) {
        return (BoolEx) field(field);
    }
    public static StrEx fieldStr(final String field) {
        return (StrEx) field(field);
    }
//    public static <T> T fieldG(final String field, final Class<T> clazz) {
//        //Arrays.asList()
//        return null;
//    }


    public static <T extends GenEx> ArrEx<T> ofArr(final List<T> ofArr) {
        return new ExArrImpl(Arrays.asList(ofArr));
    }

    public static ArrEx<IntEx> ofArr(final int... ofArr) {
        // TODO too convenient?
        return new ExArrImpl(Arrays.stream(ofArr).mapToObj(v -> of(v)).collect(Collectors.toList()));
    }
    public static <T extends GenEx> ArrEx<T> ofArr(final T... ofArr) {
        return new ExArrImpl(Arrays.asList(ofArr));
    }
    public static StrEx of(final String of) {
        // TODO strings should be treated literally
        return ExImpl.doc("$literal", of);
    }
    public static BoolEx of(final boolean of) {
        return new ExImpl(of);
    }
    public static IntEx of(final int of) {
        return new ExImpl(of);
    }
    public static NumEx of(final double of) { // TODO consumes longs
        return new ExImpl(of);
    }
    public static DateEx of(final Date of) {
        return new ExImpl(of);
    }
    @Deprecated
    public static ObjEx of(final Document of) {
        return new ExImpl(of); // TODO
    }
//    public static ObjExp of(final Object of) {
//        return new ExpImpl(of);
//    }
//    public static BoolExp ofBool(final boolean ofBool) {
//        return null;
//    }
//    public static NumExp ofNum(final int ofNum) {
//        return null;
//    }


    private Expressions() {
    }

    public static BoolEx eq(final GenEx left, final GenEx right) {
        return ExImpl.doc("$eq", asList(left, right));
    }

    public static <T extends GenEx> T ifNull(final T... abc) { // two args
        // TODO convenience for array expressions?
        return (T) ExImpl.doc("$ifNull", asList(abc));
    }


    public static <T extends GenEx> T cond(final BoolEx ifExp, final T thenExp, final T elseExp) {
        // TODO cast?
        return (T) ExImpl.doc("$cond", Arrays.asList(ifExp, thenExp, elseExp));
    }


    public static GenEx literal(final GenEx literal) {
        // TODO how does this work for expressions?
        return ExImpl.doc("$literal", literal);
    }

    public static <T extends GenEx> IntEx size(final ArrEx<T> o) {
        // TODO does this return ints or nums?
        // must wrap in a list
        return ExImpl.doc("$size", asList(o));
    }



    // -----

    public static <T extends GenEx> T arrayElemAt(final ArrEx<T> o, final IntEx o2) {
        return (T) ExImpl.doc("$arrayElemAt", asList(o, o2));
    }

    public static <T extends GenEx> T arrayElemAt(final ArrEx<T> o, final int o2) {
        return arrayElemAt(o, of(o2));
    }

    public static <T extends GenEx> BoolEx in(final T exp, final ArrEx<T> arr) {
        return ExImpl.doc("$in", asList(exp, arr));
    }

    public static <T extends GenEx> ArrEx<T> filter(final ArrEx<T> input, final BoolEx cond) {
        Document d = new Document();
        d.put("input", input);
        d.put("cond", cond);
        //d.put("as", "this");
        // TODO as, limit parameters
        return ExArrImpl.doc("$filter", d);
    }

    public static StrEx concat(final StrEx... arr) {
        return ExImpl.doc("$concat", asList(arr));
    }

    // default <R extends GenExp> ArrExp<R> map(Function<? super T, ? extends R> mapper) {
    public static <R extends GenEx, T extends GenEx> ArrEx<R> map(final ArrEx<T> input, final R in) {
        Document d = new Document();
        d.put("input", input);
        d.put("in", in);
        //d.put("as", "this");
        // TODO as, limit parameters
        return ExArrImpl.doc("$map", d);
    }

    public static NumEx sum(final GenEx... arr) {
        return ExImpl.doc("$sum", asList(arr));
    }

    public static NumEx multiply(final NumEx... arr) {
        return ExImpl.doc("$multiply", asList(arr));
    }

    public static <T extends NumEx> T add(final T... arr) {
        return (T) ExImpl.doc("$add", asList(arr));
    }

    public static NumEx year(final DateEx year) {
        // TODO date timestamp or objectId;
        return ExImpl.doc("$year", year);
    }

    public static StrEx toStr(final GenEx e) {
        return ExImpl.doc("$toString", e);
    }

    public static <T extends GenEx> T reduce(final ArrEx<T> input, final T initialValue, final GenEx in) {
        Document d = new Document();
        d.put("input", input);
        d.put("initialValue", initialValue);
        d.put("in", in);
        //d.put("as", "this");
        // TODO as, limit parameters
        return (T) ExImpl.doc("$reduce", d);
    }



    public static StrEx type(final GenEx e) {
//        if (e == null) { // TODO
//            return ExpImpl.doc("$type", null);
//        }
        return ExImpl.doc("$type", asList(e));
    }

    public static <T extends GenEx> ArrEx<T> concatArrays(final ArrEx<T>... input) {
        return ExArrImpl.doc("$concatArrays", asList(input));
    }


}
