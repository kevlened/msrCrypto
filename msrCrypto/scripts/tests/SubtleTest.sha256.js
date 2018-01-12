//*******************************************************************************
//
//    Copyright 2014 Microsoft
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
/// <reference path="testVectors/tv_sha224_short.js" />
/// <reference path="testVectors/tv_sha224_long.js" />
/// <reference path="testVectors/tv_sha256_short.js" />
/// <reference path="testVectors/tv_sha256_long.js" />

var hash256Results = [];

function hash256Complete(expectedHex, resultArray, expectedResultCount) {

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

function aesVectorTest(vectorArray, resultsArray, shaAlgName, sync) {

    expect(vectorArray.length);
    resultsArray = [];

    var vectorCount = vectorArray.length;

    shared.setAsyncState(!sync);

    for (var i = 0; i < vectorArray.length; i++) {

        var dataBytes = shared.toSupportedArray(vectorArray[i].data);
        var expectedHex = shared.bytesToHexString(vectorArray[i].hash);

        subtle.digest({ name: shaAlgName }, dataBytes)
            .then(
                
                hash256Complete(expectedHex, resultsArray, vectorArray.length),
                function (error) {

                    ok(false, error);
                    if (--vectorCount == 0) {
                        start();
                    }
                }
            );
    }
};

// #region SHA-224

module("SHA-224");

asyncTest("SHA-224 vectors short", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", false);

});

asyncTest("SHA-224 vectors short sync", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", true);

});

asyncTest("SHA-224 vectors long", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", false);

});

asyncTest("SHA-224 vectors long sync", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", true);

});


// #endregion SHA-224

// #region SHA-256

module("SHA-256");

asyncTest("SHA-256 vectors short", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", false);

});

asyncTest("SHA-256 vectors short sync", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", true);

});


asyncTest("SHA-256 vectors long", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", false);

});

asyncTest("SHA-256 vectors long sync", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", true);

});

// #endregion SHA-256



