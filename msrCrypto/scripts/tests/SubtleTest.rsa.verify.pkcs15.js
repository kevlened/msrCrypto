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
/// <reference path="testVectors/tv_rsa.verify.pkcs15.js" />

var rsa_verify_pckcs15_vector_tests = (function () {


    function vectorTest(vectorSet, sync) {
        
        var vectorCount = 0;

        // get test count
        for (var k = 0; k < vectorSet.length; k++) {
            vectorCount += vectorSet[k].vectors.length;
        }
        
        expect(vectorCount);

        for (var k = 0; k < vectorSet.length; k++) {

            var keySet = vectorSet[k];

            var testVectors = keySet.vectors;


            for (var i = 0; i < testVectors.length; i++) {

                var vector = testVectors[i];

                var keyBase = { "kty": "RSA", "extractable": true };
                keyBase.n = shared.hexStringToBase64Url(keySet.n);
                keyBase.e = shared.hexStringToBase64Url(vector.e);
                keyBase.d = shared.hexStringToBase64Url(vector.d);

                var signature = shared.hexToBytesArray(vector.signature);
                var message = shared.hexToBytesArray(vector.data);
                var algorithm = { name: "rSassa-pkcs1-v1_5", hash: { name: vector.hashName } };
                var hash = vector.hashName;
                var expected = vector.result;

                subtle.importKey("jwk", keyBase, algorithm, true, ["verify"])
                    .then(
                        (function (algorithm1, signature1, message1) {
                            return function (key) {
                                return subtle.verify(algorithm1, key, signature1, message1);
                            }
                        })(algorithm, signature, message),
                        function (error) {
                            return Promise.reject(error);
                        }
                    )
                    .then(
                        (function (expected2, hash2, iteration2, signature2, message2) {
                            return function (result) {
                                equal(
                                   expected2,
                                   result,
                                   hash2 + " [" + iteration2 + "] expected: " + expected2 +
                                   "  sig: " + shared.bytesToHexString(signature2).substring(0, 17) + "..." +
                                   "  data: " + shared.bytesToHexString(message2).substring(0, 17) + "...");

                                if (--vectorCount == 0) {
                                    start();
                                }
                            };
                        })(expected, hash, i, signature, message),
                        function (error) {
                            ok(false, error);
                            if (--vectorCount == 0) {
                                start();
                            }
                        }
                    );

            }
        }
    };

    return {
        vectorTest: vectorTest
    };

})();

module("RSA.verify.pkcs15");

// tv_rsa_verify_pkcs15 is defined in the vector file

asyncTest("vectors mod 1024", function () {

    
    rsa_verify_pckcs15_vector_tests.vectorTest(
        tv_rsa_verify_pkcs15["1024"],
        false);

});

asyncTest("vectors mod 1536", function () {

    rsa_verify_pckcs15_vector_tests.vectorTest(
        tv_rsa_verify_pkcs15["1536"],
        false);

});

asyncTest("vectors mod 2048", function () {

    rsa_verify_pckcs15_vector_tests.vectorTest(
        tv_rsa_verify_pkcs15["2048"],
        false);

});

if (shared.runSlowTests) {

    asyncTest("vectors mod 3072", function () {

        rsa_verify_pckcs15_vector_tests.vectorTest(
            tv_rsa_verify_pkcs15["3072"],
            false);

    });

    asyncTest("vectors mod 4096", function () {

        rsa_verify_pckcs15_vector_tests.vectorTest(
            tv_rsa_verify_pkcs15["4096"],
            false);

    });

}