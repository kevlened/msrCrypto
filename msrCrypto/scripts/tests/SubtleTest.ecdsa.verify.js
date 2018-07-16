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
/// <reference path="~/scripts/tests/SubtleTest.shared.js" />
/// <reference path="~/scripts/ecdsa.js" />
/// <reference path="testVectors/tv_ecdsa.verify.js" />

var ecdsa_verify_vector_tests = (function () {

    function vectorTest(curveName, vectorSet) {

        var test = msrCrypto.testInterface;

        var testCount = 0;

        for (var j = 0; j < vectorSet.length; j++) {
            testCount += vectorSet[j].vectors.length;
        }

        // We do three tests per vector
        expect(testCount);

        for (var j = 0; j < vectorSet.length; j++) {

            var vectors = vectorSet[j].vectors;

            var hashName = vectorSet[j].hashName.toLowerCase();

            for (var i = 0; i < vectors.length; i++) {

                var tv = vectors[i];

                var curve = test.cryptoECC.createCurve(curveName);

                var ecdsa = test.ecdsa(curve);

                var key = {
                    publicKey: {
                        x: shared.hexToBytes(tv.qx),
                        y: shared.hexToBytes(tv.qy)
                    }
                }

                var hashFunction = test.hashFunctions[hashName];

                var msg = hashFunction.computeHash(shared.hexToBytes(tv.data));

                var signature = shared.hexToBytes(tv.r).concat(
                    shared.hexToBytes(tv.s));

                var verified = ecdsa.verify(key.publicKey, signature, msg);

                equal(verified, tv.result, hashName + " [" + i + "] [" + tv.result + "] signature: " + shared.bytesToHexString(signature));

            }
        }

    }

    return { vectorTest: vectorTest };

})();

module("ECDSA.verify");

// These tests use the internal APIs, so they won't be available without using
// msrCrypto.test.js
if (cryptoLibraries["msrcrypto.test.js"]) {

    test("Test Vectors P-256", function () {

        _msrCrypto = msrCrypto;

        msrCrypto = cryptoLibraries["msrcrypto.test.js"];

        ecdsa_verify_vector_tests.vectorTest("P-256", tv_ecdsa_verify["P-256"]);

        msrCrypto = _msrCrypto;

    });

    test("Test Vectors P-384", function () {

        _msrCrypto = msrCrypto;

        msrCrypto = cryptoLibraries["msrcrypto.test.js"];

        ecdsa_verify_vector_tests.vectorTest("P-384", tv_ecdsa_verify["P-384"]);

        msrCrypto = _msrCrypto;

    });

    test("Test Vectors P-521", function () {

        _msrCrypto = msrCrypto;

        msrCrypto = cryptoLibraries["msrcrypto.test.js"];

        ecdsa_verify_vector_tests.vectorTest("P-521", tv_ecdsa_verify["P-521"]);

        msrCrypto = _msrCrypto;

    });

}
