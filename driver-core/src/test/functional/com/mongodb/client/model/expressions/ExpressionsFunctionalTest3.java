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

import com.mongodb.MongoCommandException;
import com.mongodb.MongoNamespace;
import com.mongodb.client.model.Field;
import com.mongodb.client.model.expressions.Expressions.IntEx;
import com.mongodb.client.test.CollectionHelper;
import org.bson.BsonArray;
import org.bson.BsonDocument;
import org.bson.BsonValue;
import org.bson.Document;
import org.bson.codecs.BsonDocumentCodec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.mongodb.ClusterFixture.getDefaultDatabaseName;
import static com.mongodb.client.model.Aggregates.addFields;
import static com.mongodb.client.model.expressions.Expressions.ArrEx;
import static com.mongodb.client.model.expressions.Expressions.BoolEx;
import static com.mongodb.client.model.expressions.Expressions.GenEx;
import static com.mongodb.client.model.expressions.Expressions.NumEx;
import static com.mongodb.client.model.expressions.Expressions.StrEx;
import static com.mongodb.client.model.expressions.Expressions.add;
import static com.mongodb.client.model.expressions.Expressions.arrayElemAt;
import static com.mongodb.client.model.expressions.Expressions.concat;
import static com.mongodb.client.model.expressions.Expressions.concatArrays;
import static com.mongodb.client.model.expressions.Expressions.cond;
import static com.mongodb.client.model.expressions.Expressions.eq;
import static com.mongodb.client.model.expressions.Expressions.field;
import static com.mongodb.client.model.expressions.Expressions.fieldArr;
import static com.mongodb.client.model.expressions.Expressions.fieldDate;
import static com.mongodb.client.model.expressions.Expressions.fieldInt;
import static com.mongodb.client.model.expressions.Expressions.fieldNum;
import static com.mongodb.client.model.expressions.Expressions.fieldObj;
import static com.mongodb.client.model.expressions.Expressions.fieldStr;
import static com.mongodb.client.model.expressions.Expressions.filter;
import static com.mongodb.client.model.expressions.Expressions.ifNull;
import static com.mongodb.client.model.expressions.Expressions.in;
import static com.mongodb.client.model.expressions.Expressions.let;
import static com.mongodb.client.model.expressions.Expressions.literal;
import static com.mongodb.client.model.expressions.Expressions.map;
import static com.mongodb.client.model.expressions.Expressions.multiply;
import static com.mongodb.client.model.expressions.Expressions.of;
import static com.mongodb.client.model.expressions.Expressions.ofArr;
import static com.mongodb.client.model.expressions.Expressions.reduce;
import static com.mongodb.client.model.expressions.Expressions.size;
import static com.mongodb.client.model.expressions.Expressions.sum;
import static com.mongodb.client.model.expressions.Expressions.toStr;
import static com.mongodb.client.model.expressions.Expressions.type;
import static com.mongodb.client.model.expressions.Expressions.variable;
import static com.mongodb.client.model.expressions.Expressions.variableArr;
import static com.mongodb.client.model.expressions.Expressions.variableInt;
import static com.mongodb.client.model.expressions.Expressions.variableStr;
import static com.mongodb.client.model.expressions.Expressions.variableThis;
import static com.mongodb.client.model.expressions.Expressions.variableThisNum;
import static com.mongodb.client.model.expressions.Expressions.year;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

public class ExpressionsFunctionalTest3 {
    private CollectionHelper<BsonDocument> helper;
    private Map<String, Object> doc;

    @BeforeEach
    public void setUp() {
        helper = new CollectionHelper<>(new BsonDocumentCodec(),
                new MongoNamespace(getDefaultDatabaseName(), getClass().getName()));
        helper.insertDocuments(BsonDocument.parse("{\n" +
                "    '_id': 1,\n" +
                "    'txt': 'abc',\n" +
                "    'num': 2,\n" +
                "    'date': ISODate(\"2021-01-15T06:31:15.000Z\"),\n" +
                "    'obj': { 'inner': 3 },\n" +
                "    'arr': [ 7, 8, 9 ]\n" +
                "}"));
        doc = new HashMap<>();
        doc.put("_id", 1);
        doc.put("txt", "abc");
        doc.put("num", 2);
    }

    @AfterEach
    public void tearDown() {
        helper.drop();
    }

    private void assertEval(final Object exp, final GenEx evaluated) {
        BsonValue x = new Document("val", exp).toBsonDocument().get("val");
        assertEquals(x, eval(evaluated));

    }

    private BsonValue eval(final GenEx expression) {
        List<BsonDocument> results = helper.aggregate(singletonList(
                addFields(new Field<>("val", expression))));
        return results.get(0).get("val");
    }

    @Test
    public void allTest() {

        // primitive literals
        assertEval(1, of(1));
        assertEval(1.0, of(1.0));
        //assertEval(1, of(1.0)); // TODO validate eq/ne of types against each other
        assertEval("abc", of("abc"));
        assertEval("$_id", of("$_id"));
        assertEval("$$NOW", of("$$NOW"));

        // fields
        assertEval(1, field("_id"));
        assertEval("abc", field("txt"));
        assertEval(2, field("num"));
        assertEval(Document.parse("{ 'inner': 3 }"), field("obj"));
        assertEval(BsonArray.parse("[7, 8, 9]"), field("arr"));
        assertEval(asList(7, 8 ,9), field("arr"));

        assertEval(3, field("obj.inner"));
        assertEval(3, field("obj.inner"));
        // TODO field.paths?


        // ------
        /*
        TODO top 50 from:
        https://docs.google.com/spreadsheets/d/1IDz9hIH7iHrs1uGCR8F0sMofUXd6s1C3weRT7iIdw6Y/edit#
        https://textedit.tools/camelcase
         */

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/eq/
        assertEval(true, eq(of(1), of(1)));
        assertEval(false, eq(of(true), of(false)));
        assertEval(true, eq(of(true), literal(of(true))));
        assertEval(true, eq(field("num"), of(2)));
        assertEval(true, eq(field("num"), of(2L))); // TODO int = long is unexpected?

        assertEval(true, field("num").eq(of(2)));
        assertEval(true, field("num").eq(2));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/cond/
        assertEval(1, cond(of(true), of(1), of(2)));
        assertEval(2, cond(of(false), of(1), of(2)));

        assertEval("no",
                cond(eq(field("num"), of(3)), of("yes"), of("no")));
        assertEval(
                doc.get("num").equals(2) ? "yes" : "no",
                field("num").eq(2).cond(of("yes"), of("no")));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/size/
        assertEval(3, size(fieldArr("arr")));

        assertEval(3,
                size(ofArr(of(1), of(2), of(3))));
        assertEval(
                asList(1, 2, 3).size(),
                ofArr(1, 2, 3).size());

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/ifNull/
        assertEval("ab", ifNull(of("ab"), of(1234)));
        assertEval(null, ifNull(field("x"), null));
        assertThrowsExactly(MongoCommandException.class, // "$ifNull needs at least two arguments"
                () -> assertEval(null, ifNull((GenEx)null)));
        assertEval(null, ifNull(null, null));

        assertEval(1234,
                ifNull(field("x"), of(1234)));
        assertEval(
                doc.getOrDefault("x", 1234),
                field("x").ifNull(of(1234)));
        assertEval(
                Optional.of(9).orElse(1234),
                of(9).ifNull(of(1234)));


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/arrayElemAt/
        ArrEx<NumEx> x = ofArr(of(1), of(2));
        assertEval(BsonArray.parse("[1, 2]"), x);
        assertEval(1, arrayElemAt(x, 0));
        assertEval(2, arrayElemAt(x, 1));
        assertEval(2, arrayElemAt(x, -1));
        //assertEval(2, arrayElemAt(x, of(1.1))); // will not compile

        assertEval(2,
                arrayElemAt(x, of(1)));
        assertEval(
                asList(1, 2, 3).get(1),
                ofArr(1, 2, 3).arrayElemAt(1));


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/ne/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/in
        assertEval(true, in(of(7), fieldArr("arr")));
        assertEval(false, in(of(2), fieldArr("arr")));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/filter
        // TODO multiple optional parameters
        assertEval(
                BsonArray.parse("[8]"),
                filter(fieldArr("arr"), eq(variableThis(), of(8))));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/gt
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/subtract
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/gte
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/concat
        assertEval("abcd", concat(fieldStr("txt"), of("d")));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/map
        assertEval(BsonArray.parse("[17, 18, 19]"),
                map(fieldArr("arr"), add(variableThisNum(), of(10))));

        ArrEx<IntEx> r1 = ofArr(1, 2, 3).map(a -> add(a, of(10)));
        ArrEx<IntEx> r2 = fieldArr("arr", IntEx.class).map(a -> a.add(10));

        assertEval(
                Stream.of(1, 2, 3)
                        .map(a -> a + 10)
                        .collect(Collectors.toList()),
                ofArr(1, 2, 3)
                        .map(a -> add(a, of(10))));



        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/divide
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/dateToString
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/or
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/sum
        assertEval(12, sum(fieldNum("num"), of(10)));
        assertEval(11.5, sum(of(1.5), of(10)));
        assertEval(11.5, sum(of(1.5), of(10), of("exclude")));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/multiply
        assertEval(20, multiply(fieldNum("num"), of(10)));
        assertEval(1500.0, multiply(of(1.5), of(10), of(100)));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/add
        assertEval(12, add(fieldNum("num"), of(10)));
        assertEval(111.5, add(of(1.5), of(10), of(100)));

        assertEval(11,
                add(of(1), of(10)));
        assertEval(
                BigInteger.ONE.add(BigInteger.TEN).intValue(),
                of(1).add(of(10)));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/year
        assertEval(1970, year(of(new Date(0))));
        assertEval(1970, of(new Date(0)).year());
        assertEval(2021, fieldDate("date").year());

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/month
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/toString
        assertEval("true|1|2.3|1970-01-01T00:00:00.000Z|", concat(
                toStr(of(true)),
                of("|"),
                toStr(of(1)),
                of("|"),
                toStr(of(2.3)),
                of("|"),
                toStr(of(new Date(0))),
                //ofArr(of("abc")) // TODO assert array fails?
                of("|")));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/objectToArray
        assertEval(Document.parse("{ 'inner': 3 }"),
                fieldObj("obj"));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/lte
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/reduce
        /*
        {
            $reduce: {
               input: ["a", "b", "c"],
               initialValue: "",
               in: { $concat : ["$$value", "$$this"] }
            }
        }
        */
        assertEval("abc",
                reduce(
                        ofArr(of("a"), of("b"), of("c")),
                        of(""),
                        concat(variableStr("value"), variableStr("this"))
                ));

        /*
        {
           $reduce: {
              input: [ 1, 2, 3, 4 ],
              initialValue: { sum: 5, product: 2 },
              in: {
                 sum: { $add : ["$$value.sum", "$$this"] },
                 product: { $multiply: [ "$$value.product", "$$this" ] }
              }
           }
        }
        */
        // TODO replace "new Document" for docs
        assertEval(BsonDocument.parse("{ 'sum' : 15, 'product' : 48 }"),
                reduce(
                        ofArr(of(1), of(2), of(3), of(4)),
                        of(new Document("sum", 5).append("product", 2)),
                        of(new Document("sum",
                                add(variable("value.sum").asNum(), variableThisNum())
                        ).append("product",
                                multiply(variable("value.product").asNum(), variableThisNum())
                        ))));

        /*
        {
           $reduce: {
              input: [ [ 3, 4 ], [ 5, 6 ] ],
              initialValue: [ 1, 2 ],
              in: { $concatArrays : ["$$value", "$$this"] }
           }
        }
         */
        assertEval(BsonArray.parse("[ 1, 2, 3, 4, 5, 6 ]"),
                reduce(
                        ofArr(ofArr(of(3), of(4)), ofArr(of(5), of(6))),
                        ofArr(of(1), of(2)),
                        concatArrays(variableArr("value"), variableArr("this"))
                ));


        assertEval(16,
                reduce(
                        ofArr(1, 2, 3),
                        of(10),
                        add(variableInt("value"), variableInt("this"))
                ));
        assertEval(
                Stream.of(1, 2, 3).reduce(10, (a, b) -> b + a),
                ofArr(1, 2, 3).reduce(of(10), (a, b) -> b.add(a)));




        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/lt
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/switch
        /*
        SwitchExpression expr = switchExpr(
                branch(literal(false), literal(1)),
                branch(literal(true), literal(2)));
        SwitchExpression expr = switchExpr(
            branch(literal(false), literal(1)),
            branch(literal(false), literal(2)))
                .defaultExpr(literal(3));
        {
            $switch: {
              branches: [
                 { case: { $eq: [ 0, 5 ] }, then: "equals" },
                 { case: { $gt: [ 0, 5 ] }, then: "greater than" }
              ],
              default: "Did not match"
           }
        }
        */
        // TODO structure and types


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/type
        //      https://www.mongodb.com/docs/manual/reference/bson-types/
        assertEval("double", type(of(1.0)));
        assertEval("string", type(of("str")));
        assertEval("object", type(of(new Document())));
        assertEval("array", type(ofArr(of(1))));
//        assertEval("binData", type(of(1)));
//        assertEval("objectId", type(of(1)));
        assertEval("bool", type(of(true)));
        assertEval("date", type(of(new Date())));
        assertEval("null", type(null));
//        assertEval("regex", type(of(1)));
//        assertEval("javascript", type(of(1)));
        assertEval("int", type(of(1)));
//        assertEval("timestamp", type(of(1)));
//        assertEval("long", type(of(1)));
//        assertEval("minKey", type(of(1)));
//        assertEval("maxKey", type(of(1)));


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/concatArrays
        assertEval(BsonArray.parse("[7, 8, 9, 1, 2, 3]"),
                concatArrays(
                        fieldArr("arr"),
                        ofArr(of(1), of(2), of(3))));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/mergeObjects
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/dayOfMonth
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/first
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/literal
        assertEval(1, field("_id"));
        assertEval("$_id", of("$_id"));
        assertEval(
                BsonDocument.parse("{'$cond': [true, 1, 2]}"),
                literal(cond(of(true), of(1), of(2))));
        // TODO literal on of(String) will cause a literal
        // assertEval("$_id", literal(of("$_id")));
//        assertEval("x", literal(size(Arrays.asList(1, 2, 3))));

        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/not
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/isArray


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/toDate
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/slice


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/convert


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/toObjectId
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/setUnion


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/toLower/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/substr/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/let/

//        NumEx e70 = let(
//                multiply(refNum("total"), refNum("discounted")),
//                bind("total", add(fieldNum("price"), fieldNum("tax"))),
//                bind("discounted", cond(fieldBool("applyDiscount"), of(0.9), of(1.0))));

        {
            int aa = 3;
            assertEval(aa + 10,
                    let(of(3), (a) -> a.add(of(10))));
        }
        {
            int aa = 3;
            int bb = 2;
            assertEval(aa + bb + 10, let(
                    of(3),
                    of(2),
                    (a, b) -> a.add(b).add(of(10))));
        }


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/max/


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/dateFromString/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/toInt/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/round/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/arrayToObject/


        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/hour/
        // https://www.mongodb.com/docs/manual/reference/operator/aggregation/meta/




    }


}
