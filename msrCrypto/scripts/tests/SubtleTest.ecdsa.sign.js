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
/// <reference path="~/scripts/ecdsa.js" />
/// <reference path="testVectors/tv_ecdsa.sign.js" />

var ecdsa_sign_vector_tests = (function () {

    function vectorTest(curveName, vectorSet) {

        var test = msrCrypto.testInterface;

        var testCount = 0,
            j;

        for (j = 0; j < vectorSet.length; j++) {
            testCount += vectorSet[j].vectors.length;
        }

        // We do three tests per vector
        expect(testCount * 3);

        for (j = 0; j < vectorSet.length; j++) {

            var vectors = vectorSet[j].vectors;

            var hashName = vectorSet[j].hashName.toLowerCase();

            for (var i = 0; i < vectors.length; i++) {

                var tv = vectors[i];

                var curve = test.cryptoECC["createP" + curveName]();

                var ecdsa = test.ecdsa(curve);

                var key = ecdsa.createKey(shared.hexToBytes(tv.d));

                key = {
                    privateKey: {
                        d: test.cryptoMath.digitsToBytes(key.privateKey)
                    },
                    publicKey: {
                        x: test.cryptoMath.digitsToBytes(key.publicKey.x),
                        y: test.cryptoMath.digitsToBytes(key.publicKey.y)
                    }
                };

                var hashFunction = test.hashFunctions[hashName];

                var msg = hashFunction.computeHash(shared.hexToBytes(tv.data));

                var ephemeralKey = ecdsa.createKey(shared.hexToBytes(tv.k));

                var signature = ecdsa.sign(key.privateKey, msg, ephemeralKey);

                var actualR = shared.bytesToHexString(signature.slice(0, signature.length / 2));

                var actualS = shared.bytesToHexString(signature.slice(-(signature.length / 2)));

                var expectedR = shared.bytesToHexString(shared.hexToBytes(tv.r));

                var expectedS = shared.bytesToHexString(shared.hexToBytes(tv.s));

                var verified = ecdsa.verify(key.publicKey, signature, msg);

                ok(verified, hashName + " [" + i + "] signature: " + shared.bytesToHexString(signature));
                equal(actualR, expectedR, "expected r = " + actualR);
                equal(actualS, expectedS, "expected s = " + actualS);

            }
        }

    }

    return { vectorTest: vectorTest };

})();

module("ECDSA.sign");

asyncTest("GenerateKey P-256", function () {

    var algorithm = { name: "Ecdsa", namedCurve: "P-256" };

    subtle.generateKey(algorithm, true, ["sign", "verify"]).then(
        function (keyPair) {
            shared.getKeyData(keyPair.publicKey, function (publicKeyObject) {

                shared.getKeyData(keyPair.privateKey, function (priKey, pubKey) {

                    start();

                    equal(keyPair.publicKey.type, "public");
                    equal(keyPair.publicKey.algorithm.name.toLowerCase(), "ecdsa");
                    equal(keyPair.publicKey.algorithm.namedCurve.toLowerCase(), "p-256");

                    equal(pubKey.kty.toLowerCase(), "ec");
                    equal(pubKey.crv.toLowerCase(), "p-256");
                    equal(shared.base64UrlToBytes(pubKey.x).length, 32);
                    equal(shared.base64UrlToBytes(pubKey.y).length, 32);

                    equal(keyPair.privateKey.type, "private");
                    equal(keyPair.privateKey.algorithm.name.toLowerCase(), "ecdsa");
                    equal(keyPair.privateKey.algorithm.namedCurve.toLowerCase(), "p-256");

                    equal(priKey.kty.toLowerCase(), "ec");
                    equal(priKey.crv.toLowerCase(), "p-256");
                    equal(shared.base64UrlToBytes(priKey.d).length, 32);
                    equal(shared.base64UrlToBytes(priKey.x).length, 32);
                    equal(shared.base64UrlToBytes(priKey.y).length, 32);

                }, publicKeyObject);

            });
        },
        function (error) {
            var a = error;
        }
    );
});

asyncTest("GenerateKey P-384", function () {

    var algorithm = { name: "Ecdsa", namedCurve: "P-384" };

    subtle.generateKey(algorithm, true, ["sign", "verify"]).then(
        function (keyPair) {

            shared.getKeyData(keyPair.publicKey, function (publicKeyObject) {

                shared.getKeyData(keyPair.privateKey, function (priKey, pubKey) {

                    start();

                    equal(keyPair.publicKey.type, "public");
                    equal(keyPair.publicKey.algorithm.name.toLowerCase(), "ecdsa");
                    equal(keyPair.publicKey.algorithm.namedCurve.toLowerCase(), "p-384");

                    equal(pubKey.kty.toLowerCase(), "ec");
                    equal(pubKey.crv.toLowerCase(), "p-384");
                    equal(shared.base64UrlToBytes(pubKey.x).length, 48);
                    equal(shared.base64UrlToBytes(pubKey.y).length, 48);

                    equal(keyPair.privateKey.type, "private");
                    equal(keyPair.privateKey.algorithm.name.toLowerCase(), "ecdsa");
                    equal(keyPair.privateKey.algorithm.namedCurve.toLowerCase(), "p-384");

                    equal(priKey.kty.toLowerCase(), "ec");
                    equal(priKey.crv.toLowerCase(), "p-384");
                    equal(shared.base64UrlToBytes(priKey.d).length, 48);
                    equal(shared.base64UrlToBytes(priKey.x).length, 48);
                    equal(shared.base64UrlToBytes(priKey.y).length, 48);

                }, publicKeyObject);

            });
        },
        shared.error("Generate key error")
    );
});

asyncTest("Sign & Verify P-256 SHA-256", function () {
    
    subtle.generateKey({ name: "Ecdsa", namedCurve: "P-256" }, true, ["sign", "verify"]).then(

        function (keyPair) {

            var data = [];

            for (var j = 0; j < Math.random() * 300; j++) {
                data.push(Math.random() * 256);
            }

            data = shared.toSupportedArray(data);

            var algorithm = { name: "Ecdsa", namedCurve: "P-256", hash: { name: "SHA-256" } };

            subtle.sign(algorithm, keyPair.privateKey, data).then(

                function (e) {

                    var signatureBytes = shared.toSupportedArray(e);

                    var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

                        function (e) {

                            var result = e;

                            start();

                            ok(result, "s = " + shared.bytesToHexString(signatureBytes));
                        },
                        shared.error("Verify error")
                    );

                },
                shared.error("Sign error")
            );
        },
        shared.error("Generate key error")
    );
});

asyncTest("Sign & Verify P-384 SHA-256", function () {

    subtle.generateKey({ name: "Ecdsa", namedCurve: "P-384" }, true, ["sign", "verify"]).then(

        function (keyPair) {

            var data = [];

            for (var j = 0; j < Math.random() * 300; j++) {
                data.push(Math.random() * 256);
            }

            data = shared.toSupportedArray(data);

            var algorithm = { name: "Ecdsa", namedCurve: "p-384", hash: { name: "Sha-256" } };

            subtle.sign(algorithm, keyPair.privateKey, data).then(

                function (e) {

                    var signatureBytes = shared.toSupportedArray(e);

                    var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

                        function (result) {
                            start();
                            ok(result, "s = " + shared.bytesToHexString(signatureBytes));
                        },
                        shared.error("Verify error")
                    );

                },
                shared.error("Sign error")
            );
        },
        shared.error("Generate key error")
    );

});

asyncTest("Sign & Verify NUMSP256D1 SHA-256", function () {

    subtle.generateKey({ name: "Ecdsa", namedCurve: "numsp256d1" }, true, ["sign", "verify"]).then(

        function (keyPair) {

            var data = [];

            for (var j = 0; j < Math.random() * 300; j++) {
                data.push(Math.floor(Math.random() * 256));
            }

            data = shared.toSupportedArray(data);

            var algorithm = { name: "Ecdsa", namedCurve: "numsp256d1", hash: { name: "Sha-256" } };

            subtle.sign(algorithm, keyPair.privateKey, data).then(

                function (e) {

                    var signatureBytes = shared.toSupportedArray(e);

                    var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

                        function (result) {
                            start();
                            ok(result, "s = " + shared.bytesToHexString(signatureBytes));
                        },
                        shared.error("Verify error")
                    );

                },
                shared.error("Sign error")
            );

        },
        shared.error("Generate key error")
    );

});

asyncTest("Sign & Verify NUMSP384D1 SHA-256", function () {

    subtle.generateKey({ name: "Ecdsa", namedCurve: "NUMSP384D1" }, true, ["sign", "verify"]).then(

        function (e) {

            var keyPair = e;

            var data = [];

            for (var j = 0; j < Math.random() * 300; j++) {
                data.push(Math.random() * 256);
            }

            data = shared.toSupportedArray(data);

            var algorithm = { name: "Ecdsa", namedCurve: "NUMSP384D1", hash: { name: "Sha-256" } };

            subtle.sign(algorithm, keyPair.privateKey, data).then(

                function (e) {

                    var signatureBytes = shared.toSupportedArray(e);

                    var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

                        function (e) {

                            var result = e;

                            start();

                            ok(result, "s = " + shared.bytesToHexString(signatureBytes));
                        },
                        shared.error("Verify error")
                    );
                },
                shared.error("Sign error")
            );
        },
        shared.error("Generate key error")
    );
});

//asyncTest("Sign & Verify NUMSP512D1 SHA-256", function () {

//    subtle.generateKey({ name: "Ecdsa", namedCurve: "NUMSP512D1" });

//    function (e) {

//        var keyPair = e;

//        var data = [];

//        for (var j = 0; j < Math.random() * 300; j++) {
//            data.push(Math.random() * 256);
//        }

//        var algorithm = { name: "Ecdsa", namedCurve: "NUMSP512D1", hash: { name: "Sha-256" } };

//        subtle.sign(algorithm, keyPair.privateKey, data).then(

//        function (e) {

//            var signatureBytes = shared.getArrayResult(e);

//            var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

//            function (e) {

//                var result = e;

//                start();

//                ok(result, "s = " + shared.bytesToHexString(signatureBytes));
//            };

//            shared.error("Verify error");

//        };

//        cryptoOp.onerror = shared.error("Sign error");
//    };

//    keyGenOp.onerror = shared.error("Generate key error");

//});

asyncTest("Sign & Verify NUMSP256T1 SHA-256", function () {

    var results = [];
    subtle.generateKey({ name: "Ecdsa", namedCurve: "NUMSP256T1" }, true, ["sign", "verify"]).then(

        function (keyPair) {

            var data = [];

            for (var j = 0; j < Math.floor(Math.random() * 300) ; j++) {
                data.push(Math.floor(Math.random() * 256));
            }

            data = shared.toSupportedArray(data);

            var algorithm = { name: "Ecdsa", namedCurve: "NUMSP256T1", hash: { name: "Sha-256" } };

            subtle.sign(algorithm, keyPair.privateKey, data).then(

                function (e) {

                    var signatureBytes = shared.toSupportedArray(e);

                    var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

                        function (result) {
                            start();
                            ok(result, "s = " + shared.bytesToHexString(signatureBytes));
                        },
                        shared.error("Verify error")
                    );
                },
                shared.error("Sign error")
            );
        },
        shared.error("Generate key error")
    );

});

asyncTest("Sign & Verify NUMSP384T1 SHA-256", function () {

    subtle.generateKey({ name: "Ecdsa", namedCurve: "NUMSP384T1" }, true, ["sign", "verify"]).then(

        function (keyPair) {

            var data = [];

            for (var j = 0; j < Math.random() * 384; j++) {
                data.push(Math.floor(Math.random() * 256));
            }

            data = shared.toSupportedArray(data);

            var algorithm = { name: "Ecdsa", namedCurve: "NUMSP384T1", hash: { name: "Sha-256" } };

            subtle.sign(algorithm, keyPair.privateKey, data).then(

                function (e) {

                    var signatureBytes = shared.toSupportedArray(e);

                    var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

                        function (result) {
                            start();
                            ok(result, "s = " + shared.bytesToHexString(signatureBytes));
                        },
                        shared.error("Verify error")
                    );

                },
                shared.error("Sign error")
            );

        },
        shared.error("Generate key error")
    );

});

//asyncTest("Sign & Verify NUMSP512T1 SHA-256", function () {

//    subtle.generateKey({ name: "Ecdsa", namedCurve: "NUMSP512T1" });

//    function (e) {

//        var keyPair = e;

//        var data = [];

//        for (var j = 0; j < Math.random() * 384; j++) {
//            data.push(Math.floor(Math.random() * 256));
//        }

//        var algorithm = { name: "Ecdsa", namedCurve: "NUMSP512T1", hash: { name: "Sha-256" } };

//        subtle.sign(algorithm, keyPair.privateKey, data).then(

//        function (e) {

//            var signatureBytes = shared.getArrayResult(e);

//            var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data).then(

//            function (e) {

//                var result = e;

//                start();

//                ok(result, "s = " + shared.bytesToHexString(signatureBytes));
//            };

//            shared.error("Verify error");

//        };

//        cryptoOp.onerror = shared.error("Sign error");

//    };

//    keyGenOp.onerror = shared.error("Generate key error");

//});

