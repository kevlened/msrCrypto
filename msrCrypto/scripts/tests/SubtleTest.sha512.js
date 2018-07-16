//*******************************************************************************
//
//    Copyright 2018 Microsoft
//    
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//    
//        http://www.apache.org/licenses/LICENSE-2.0
//    
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//*******************************************************************************

/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.15.0.js" />
/// <reference path="test512Vectors/tv_sha384_short.js" />
/// <reference path="test512Vectors/tv_sha384_long.js" />
/// <reference path="test512Vectors/tv_sha384_short.js" />
/// <reference path="test512Vectors/tv_sha384_long.js" />

var hash512Results = [];

function hash512Complete(expectedHex, resultArray, expectedResultCount) {

    return function (result) {

        var hashHex = shared.bytesToHexString(shared.getArrayResult(result));
        resultArray.push({ hash: hashHex, expected: expectedHex });

        if (resultArray.length === expectedResultCount) {
            start();
            for (var i = 0; i < resultArray.length; i++) {
                equal(resultArray[i].hash, resultArray[i].expected, "should be " + resultArray[i].expected);
            }
        }

    };
};

function test512Vectors(vectors, algorithmName, resultsArray, async) {

    expect(vectors.length);
    resultsArray = [];

    shared.setAsyncState(async);

    var cryptoOp;

    for (var i = 0; i < vectors.length; i++) {

        var dataBytes = shared.toSupportedArray(vectors[i].data);
        var expectedHex = shared.bytesToHexString(vectors[i].hash);

        cryptoOp = subtle.digest({ name: algorithmName }, dataBytes).then(
            hash512Complete(expectedHex, resultsArray, vectors.length)
            );
    }
}

// #region SHA-384

module("SHA-384");

asyncTest("SHA-384 vectors short", function () {

    test512Vectors(testVectorsSha384Short, "sha-384", hash512Results, true);

});

asyncTest("SHA-384 vectors long", function () {

    test512Vectors(testVectorsSha384Long, "sha-384", hash512Results, true);

});

asyncTest("SHA-384 vectors short sync", function () {

    test512Vectors(testVectorsSha384Short, "sha-384", hash512Results, false);

});

asyncTest("SHA-384 vectors long sync", function () {

    test512Vectors(testVectorsSha384Long, "sha-384", hash512Results, false);

});

// #endregion SHA-384

// #region SHA-512

module("SHA-512");

asyncTest("SHA-512 vectors short", function () {

    test512Vectors(testVectorsSha512Short, "sha-512", hash512Results, true);

});

asyncTest("SHA-512 vectors long", function () {

    test512Vectors(testVectorsSha512Long, "sha-512", hash512Results, true);

});

asyncTest("SHA-512 vectors short sync", function () {

    test512Vectors(testVectorsSha512Short, "sha-512", hash512Results, false);

});

asyncTest("SHA-512 vectors long sync", function () {

    test512Vectors(testVectorsSha512Long, "sha-512", hash512Results, false);

});

// #endregion SHA-512