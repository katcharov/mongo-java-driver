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

public final class ExpressionAny {

    private static interface AnyExp extends NumExp, StrExp, BoolExp {

    }
    private static interface NumExp {

    }
    private static interface BoolExp {

    }
    private static interface StrExp {

    }

    private void test() {
        // Any is an interface that extends Bool, Str, Num.
        // This is the reverse of what is usually expected.

        // Still, most compositions behave in a normal way:

        // eq takes Any (not T) and returns a Bool
        BoolExp boolExp = eq(of("a"), of("b"));
        // cond (uses T) returns as expected for Num
        NumExp x1 = cond(boolExp, ofNum(1), ofNum(2));
        // it also blocks expressions known to be Num in the Bool position:
        // NumExp x2 = cond(/*error:*/ofNum(0), ofNum(1), ofNum(2));
        // fields are Any, because their type is unknown
        AnyExp x2 = cond(boolExp, field("x"), field("y"));

        // However, we start to run into trouble with other compositions:

        // Any (fields) can be used in place of Bool, without type-casting:
        BoolExp x3 = cond(field("unknown"), ofBool(true), ofBool(false));

        // But since cond returns T, it infers Object, not Any (a subtype)
        Object x4 = cond(boolExp, ofBool(true), ofNum(1));

        // We would need to explicitly specify Any, which is unintuitive:
        AnyExp x5 = cond(boolExp, ofAny(true), ofAny(1));

        // Or we can return Any to seemingly fix this:
        AnyExp x6 = cond2(boolExp, ofBool(true), ofNum(1));

        // But then we are allowed to write the following:
        StrExp x7 = cond2(boolExp, ofBool(true), ofBool(false));

        // This approach allows us to use fields of unknown types
        // where (for example) Bool is required, and offers partial
        // type-checking by disallowing types known to be (eg) Num.

        // But this partial type-checking is confusing, and there
        // seems to be no way for it to be conceptually coherent.
    }

    private AnyExp field(String field) {
        return null;
    }


    private AnyExp of(String of) {
        return null;
    }
    private AnyExp of(boolean o) {
        return null;
    }
    private BoolExp ofBool(boolean ofBool) {
        return null;
    }
    private AnyExp ofAny(Object ofAny) {
        return null;
    }
    private NumExp ofNum(int ofNum) {
        return null;
    }


    private ExpressionAny() {
    }

    public static BoolExp eq(AnyExp left, AnyExp right) {
        return null;
    }
    public static Object ifNull(Object... abc) { // two args
        return null;
    }
    public static <T> T cond(BoolExp ifExp, T thenExp, T elseExp) {
        return null;
    }
    public static <T> AnyExp cond2(BoolExp ifExp, T thenExp, T elseExp) {
        return null;
    }
    public static Object literal(Object o) {
        return null;
    }
    public static Object size(Object o) {
        return null;
    }
    public static Object arrayElemAt(Object o, Object o2) {
        return null;
    }
    public static Object add(Object left, Object right) {
        return null;
    }
}
