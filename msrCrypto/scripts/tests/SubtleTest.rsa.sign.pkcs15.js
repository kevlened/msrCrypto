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
/// <reference path="~/scripts/tests/SubtleTest.shared.js" />
/// <reference path="testVectors/tv_rsa.sign.pkcs15.js" />

var rsa_sign_pckcs15_vector_tests = (function () {

    var results = [];

    function importRsaKey(keyData, algorithm, callback, errorCallback) {

        subtle.importKey("jwk", keyData, algorithm, true, ["sign"]).then(
            function (e) {
                callback(e);
            },
            function (e) {
                errorCallback(e);
            }
        );
    }

    function signComplete(hashName, expectedHex, resultArray, expectedResultCount) {

        return function (e) {

            var signatureHex = shared.bytesToHexString(shared.getArrayResult(e))
            resultArray.push({ hash: hashName, signature: signatureHex, expected: expectedHex });

            if (resultArray.length === expectedResultCount) {
                start();
                for (var i = 0; i < resultArray.length; i++) {
                    equal(
                        resultArray[i].signature,
                        resultArray[i].expected,
                        resultArray[i].hash + " " + resultArray[i].expected);
                }
            }

        };
    };

    function vectorTest(key, vectors, sync) {

        expect(vectors.length);
        results = [];

        shared.setAsyncState(!sync);

        var keyBase = { "kty": "RSA", "ext": true };
        keyBase.n = shared.hexStringToBase64Url(key.n);
        keyBase.e = shared.hexStringToBase64Url(key.e);
        keyBase.d = shared.hexStringToBase64Url(key.d);

        var algorithm = {
            name: "rsassa-pkcs1-v1_5",
            hash: { name: "SHA-256" }
        }

        importRsaKey(keyBase, algorithm, function (keyHandle) {

            for (var i = 0; i < vectors.length; i++) {

                var hash = vectors[i].hashName;
                var dataBytes = shared.hexToBytesArray(vectors[i].data);
                var expectedHex =
                    shared.bytesToHexString(
                        shared.hexToBytesArray(vectors[i].signature)
                        );

                algorithm.hash.name = hash;

                subtle.sign({ name: "rsassa-pkcs1-v1_5", hash: { name: hash } }, keyHandle, dataBytes)
                    .then(

                        signComplete(hash, expectedHex, results, vectors.length),

                        function (error) {
                            ok(false, error);
                        }
                );

            }

        }, shared.error("key import error"));
    };

    return {
        vectorTest: vectorTest
    };

})();

module("RSA.sign.pkcs15");

// tv_rsa_sign_pkcs15 is defined in the vector file

asyncTest("vectors mod 1024", function () {

    rsa_sign_pckcs15_vector_tests.vectorTest(
        tv_rsa_sign_pkcs15.keys["1024"],
        tv_rsa_sign_pkcs15.vectors["1024"],
        false);

});

asyncTest("vectors mod 1536", function () {

    rsa_sign_pckcs15_vector_tests.vectorTest(
        tv_rsa_sign_pkcs15.keys["1536"],
        tv_rsa_sign_pkcs15.vectors["1536"],
        false);

});

asyncTest("vectors mod 2048", function () {

    rsa_sign_pckcs15_vector_tests.vectorTest(
        tv_rsa_sign_pkcs15.keys["2048"],
        tv_rsa_sign_pkcs15.vectors["2048"], false);

});

if (shared.runSlowTests) {

    asyncTest("vectors mod 3072", function () {

        rsa_sign_pckcs15_vector_tests.vectorTest(
            tv_rsa_sign_pkcs15.keys["3072"],
            tv_rsa_sign_pkcs15.vectors["3072"],
            false);

    });


    asyncTest("vectors mod 4096", function () {

        rsa_sign_pckcs15_vector_tests.vectorTest(
            tv_rsa_sign_pkcs15.keys["4096"],
            tv_rsa_sign_pkcs15.vectors["4096"],
            false);

    });

}




