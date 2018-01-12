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
/// <reference path="testVectors/tv_rsa.sign.pss.js" />

var rsa_sign_pss_vector_tests = (function () {


    function vectorTest(key, vectors, sync) {

        expect(vectors.length);

        var vectorCount = vectors.length;

        var keyBase =
            {
                kty: "RSA",
                ext: true,
                n: shared.hexStringToBase64Url(key.n),
                e: shared.hexStringToBase64Url(key.e),
                d: shared.hexStringToBase64Url(key.d)
            };

        subtle.importKey("jwk", keyBase, { name: "rSa-pss", hash: { name: vectors[0].hashName } }, true, ["sign"])
            .then(

                function (key) {

                    for (var i = 0; i < vectors.length; i++) {

                        var vector = vectors[i],
                            hash = vector.hashName,
                            dataBytes = shared.hexToBytesArray(vector.data),
                            saltBytes = shared.hexToBytesArray(vector.salt),
                            expectedHex = shared.bytesToHexString(shared.hexToBytesArray(vector.signature));

                        subtle.sign({ name: "rSa-pss", hash: { name: hash }, salt: saltBytes }, key, dataBytes)
                            .then(
                                (function (hash1, expectedHex1) {
                                    return function (result) {
                                        var signatureHex = shared.bytesToHexString(shared.getArrayResult(result));
                                        equal(signatureHex, expectedHex1, hash1 + ": " + signatureHex.substring(0, 17) + "... == " + expectedHex1.substring(0, 17) + "...");

                                        if (--vectorCount == 0) {
                                            start();
                                        }

                                    };
                                })(hash, expectedHex),
                                function (error) {
                                    ok(false, error);
                                    if (--vectorCount == 0) {
                                        start();
                                    }
                                }
                            );

                    }
                },

                // Reject
                function (error) {
                    QUnit.start();
                    ok(false, error);
                }
            );

        return;
    }

    return {
        vectorTest: vectorTest
    };

})();

module("RSA.sign.pss");

asyncTest("vectors mod 1024", function () {

    rsa_sign_pss_vector_tests.vectorTest(
        tv_rsa_sign_pss.keys["1024"],
        tv_rsa_sign_pss.vectors["1024"],
        false);

});

asyncTest("vectors mod 2048", function () {

    rsa_sign_pss_vector_tests.vectorTest(
        tv_rsa_sign_pss.keys["2048"],
        tv_rsa_sign_pss.vectors["2048"],
        false);

});

if (shared.runSlowTests) {

    asyncTest("vectors mod 3072", function () {

        rsa_sign_pss_vector_tests.vectorTest(
            tv_rsa_sign_pss.keys["3072"],
            tv_rsa_sign_pss.vectors["3072"],
            false);

    });

}





