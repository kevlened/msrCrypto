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
/// <reference path="testVectors/tv_sha1_short.js" />
/// <reference path="testVectors/tv_sha1_long.js" />

var hash1Results = [];

function hash1Complete(expectedHex, resultArray, expectedResultCount) {

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

function vectorTest(vectorArray, resultsArray, shaAlgName, sync) {

    expect(vectorArray.length);
    resultsArray = [];

    shared.setAsyncState(!sync);

    for (var i = 0; i < vectorArray.length; i++) {

        var dataBytes = shared.hexToBytesArray(vectorArray[i].data);
        var expectedHex = shared.bytesToHexString(shared.hexToBytesArray(vectorArray[i].hash));

        var cryptoOp = subtle.digest({ name: shaAlgName }, dataBytes).then(
            hash1Complete(expectedHex, resultsArray, vectorArray.length));
    }
}

// #region SHA-1

module("SHA-1");

asyncTest("vectors short", function () {

    vectorTest(testVectorsSha1Short, hash1Results, "SHA-1", false);

});


asyncTest("vectors short sync", function () {

    vectorTest(testVectorsSha1Short, hash1Results, "sHa-1", true);

});

asyncTest("vectors long", function () {

    vectorTest(testVectorsSha1Long, hash1Results, "Sha-1", false);

});


asyncTest("vectors long sync", function () {

    vectorTest(testVectorsSha1Long, hash1Results, "shA-1", true);

});

// #endregion SHA-1



