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
/// <reference path="testVectors/tv_aes.js" />

var aesCbcTest = {

    aesResults1: [],
    aesResults2: [],
    aesResults3: [],

    waitAes: function (array, length) {
        if (array.length >= length) {
            start();
            for (var i = 0; i < length; i++) {
                equal(shared.bytesToHexString(array[i].result),
                      shared.bytesToHexString(array[i].expected),
                      "tag " + array[i].tag);
            }

        } else {
            setTimeout(
                function () {
                    aesCbcTest.waitAes(array, length);
                }, 100);
        }
    },

    aesComplete: function (resultArray, encryptedBytes, expectedBytes, plainTextBytes, tag) {

        return function (e) {
            var result = shared.toSupportedArray(e);
            resultArray.push({ result: encryptedBytes, expected: expectedBytes, tag: "enc" });
            resultArray.push({ result: result, expected: plainTextBytes, tag: "dec" });
        };

    },

    aesEncryptionComplete: function (expected) {
        return function (e) {
            start();
            var hashBytes = shared.getArrayResult(e);
            var result = shared.bytesToHexString(hashBytes);
            var expectedHex = shared.bytesToHexString(expected);
            equal(result, expectedHex, "should be " + expectedHex);
        };
    },

    aesDecryptionComplete: function (expected) {
        return function (e) {
            start();
            var decryptedBytes = shared.getArrayResult(e);
            var result = String.fromCharCode.apply(null, decryptedBytes);
            var expectedString = String.fromCharCode.apply(null, expected);
            equal(result, expectedString, "should be " + expectedString);
        };
    },

    aesEncrypt: function (keyBytes, dataBytes, ivBytes, expectedBytes, sync, process) {

        var cryptoOp;

        subtle.forceSync = sync;

        shared.importKey("aes-cbc", keyBytes, function (key) {

            subtle.encrypt({ name: "Aes-CBC", iv: ivBytes }, key, dataBytes).then(
                aesCbcTest.aesEncryptionComplete(expectedBytes),
                shared.error()
            )

        }, shared.error());

    },

    aesDecrypt: function (keyBytes, encryptedBytes, ivBytes, expectedBytes, sync, process) {

        subtle.forceSync = sync;

        shared.importKey("aes-cbc", keyBytes, function (key) {

            subtle.decrypt({ name: "Aes-CBC", iv: ivBytes }, key, encryptedBytes).then(
                aesCbcTest.aesDecryptionComplete(expectedBytes),
                shared.error()
            );

        }, shared.error("aesDecrypt"));

    },

    aesRoundTrip: function (resultsArray, keyBytes, dataBytes, ivBytes, expectedBytes, sync, process) {

        var cryptoOpEnc, cryptoOpDec;

        subtle.forceSync = sync;

        var jwkKeyString = shared.toBase64(keyBytes);
        jwkKeyString = jwkKeyString.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        jwkKeyString = shared.keyTextToKeyData("aes", jwkKeyString);

        shared.importKey("aes-cbc", jwkKeyString, function (key) {

            subtle.encrypt({ name: "Aes-CBC", iv: ivBytes }, key, dataBytes).then(

                function (result) {
                    var encryptedBytes = shared.getArrayResult(result);
                    subtle.decrypt({ name: "Aes-CBC", iv: ivBytes }, key, shared.toSupportedArray(encryptedBytes)).then(
                        aesCbcTest.aesComplete(resultsArray, Array.apply([], encryptedBytes), expectedBytes, dataBytes, keyBytes.length.toString()),
                        shared.error()
                    );
                },
                shared.error()
            );
        }, shared.error());

    },

    aesGenerateKey: function (keySize, sync) {

        expect(5);

        var aesKey = null;

        subtle.forceSync = sync;

        var keyOpGen = subtle.generateKey({ name: "AES-CBC", length: keySize }, true, ["encrypt"]).then(

        function (aesKey) {


            subtle.exportKey("jwk", aesKey, true, ["encrypt"]).then(
                (function (key) {
                    return function (keyObject) {

                        keyBytes = Array.apply(null,shared.base64UrlToBytes(keyObject.k));

                        start();

                        equal(key.type, "secret", "secret key type");
                        equal(key.algorithm.name.toUpperCase(), "AES-CBC", "aes-cbc algorithm name");

                        equal(keyBytes.length, keySize / 8, "expected number of bytes: " + keyBytes.join());
                        equal(keyObject.kty, "oct", "kty=oct");

                        equal(keyObject.alg, "A" + keySize + "CBC", "expected alg " + keyObject.alg);

                    }
                })(aesKey),
                function (e) {
                    ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
                }
            );
        },
            function (e) {
                start();
                ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
            }
        );
    },

    aesProcessError: function () {

        var subtle = msCrypto.subtle,
            aesKey,
            iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            plain = new Uint8Array(100);

        // Create some data
        for (var i = 0; i < plain.length; i++) {
            plain[i] = i;
        }

        var keyOpGen = subtle.generateKey({ name: "Aes-cbc", length: 256 });

        keyOpGen.oncomplete = function (e) {

            aesKey = e.target.result;

            var cryptoOpEnc = subtle.encrypt({ name: "Aes-CBC", iv: iv }, aesKey, plain);

            cryptoOpEnc.oncomplete = function (e1) {

                var cipherBytes = new Uint8Array(e1.target.result);

                cryptoOpDec = subtle.decrypt({ name: "Aes-CBC", iv: iv }, aesKey);

                cryptoOpDec.oncomplete = function (e2) {

                    var plainResultBytes = new Uint8Array(e2.target.result);

                    if (!arraysEqual(plain, plainResultBytes)) {
                        alert("Origninal [" + plain.length + "] " + Array.apply(null, plain).join() + '\n\n' +
                           "Decrypted [" + plainResultBytes.length + "] " + Array.apply(null, plainResultBytes).join());
                    }

                    alert("Success");
                }

                cryptoOpDec.onerror = error("Decryption Error");

                // Process the data byte-by-byte
                var dataByte = new Uint8Array(1);
                for (var i = 0; i < cipherBytes.length; i++) {
                    dataByte[0] = cipherBytes[i];
                    cryptoOpDec.process(dataByte);
                }
                cryptoOpDec.finish();
            };

            cryptoOpEnc.onerror = error("Encryption Error");

            // Process the data byte-by-byte
            var dataByte = new Uint8Array(1);
            for (var i = 0; i < plain.length; i++) {
                dataByte[0] = plain[i];
                cryptoOpEnc.process(dataByte);
            }
            cryptoOpEnc.finish();
        };


        keyOpGen.onerror = error("KeyGen Error");

        function arraysEqual(array1, array2) {
            if (array1.length !== array2.length) { return false; }
            for (var i = 0; i < array1.length; i++) {
                if (array1[i] !== array2[i]) { return false; }
            }
            return true;
        }

        function error(label) {
            return function (e) {
                alert(label + " : " + e.message || e.error);
            }
        }

    }

};


module("AES-CBC");

asyncTest("GenerateKey 128 Sync", function () {

    aesCbcTest.aesGenerateKey(128, true);

});

asyncTest("GenerateKey 192 Sync", function () {

    aesCbcTest.aesGenerateKey(192, true);

});

asyncTest("GenerateKey 256 Sync", function () {

    aesCbcTest.aesGenerateKey(256, true);

});

asyncTest("GenerateKey 128 Async", function () {

    aesCbcTest.aesGenerateKey(128, false);

});

asyncTest("GenerateKey 192 Async", function () {

    aesCbcTest.aesGenerateKey(192, false);

});

asyncTest("GenerateKey 256 Async", function () {

    aesCbcTest.aesGenerateKey(256, false);

});

asyncTest("KeyImport/Export Sync", function () {

    expect(4);

    //clear the global key handle
    aesKey = null;

    subtle.forceSync = true;


    var keyData = {
        kty: "oct",
        k: "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"
    }

    subtle.importKey("jwk", keyData, { name: "Aes-cbc" }, true, ["encrypt"]).then(

        function (aesKey) {

            subtle.exportKey("jwk", aesKey, { name: "Aes-cbc" }, true, ["encrypt"]).then(
                (function (key) {
                    return function (keyObject) {
                        start();
                        equal(key.type, "secret", "secret key type");
                        equal(key.algorithm.name.toLowerCase(), "aes-cbc", "aes-cbc algorithm name");
                        equal(keyObject.k, keyData.k, "k");
                        equal(keyObject.kty, "oct", "kty");
                    }
                })(aesKey),
                function (e) {
                    ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
                }
            );
        },
        function (e) {
            start();
            ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
        }
    );
});

asyncTest("KeyImport/Export Async", function () {

    expect(4);

    //clear the global key handle
    var aesKey = null;

    delete subtle.forceSync;

    var keyData = {
        kty: "oct",
        k: "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"
    }

    var keyOpImp = subtle.importKey("jwk", keyData, { name: "Aes-cbc" }, true, ["decrypt"]).then(

        function (result) {

            aesKey = result;

            subtle.exportKey("jwk", aesKey, { name: "Aes-cbc" }, true, ["sign"]).then(
                (function (key) {
                    return function (keyObject) {
                        start();
                        equal(key.type, "secret", "secret key type");
                        equal(key.algorithm.name.toLowerCase(), "aes-cbc", "aes-cbc algorithm name");
                        equal(keyObject.k, keyData.k, "k");
                        equal(keyObject.kty, "oct", "kty");
                    }
                })(aesKey),
                function (e) {
                    ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
                }
            );
        },
        function (e) {
            start();
            ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
        }
    );

});

asyncTest("Encrypt Async", function () {

    aesCbcTest.aesEncrypt(
        shared.keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        false,
        false
    );

});

asyncTest("Encrypt Sync", function () {

    aesCbcTest.aesEncrypt(
        shared.keyTextToKeyData("aes", "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.hexToBytesArray("8CD084B7-35ECE917-E6A27079-3273B548-DA95CE63-2EB9AD13-7154F623-44C73D97"),
        true,
        false
    );

});

asyncTest("Encrypt Async Process", function () {

    aesCbcTest.aesEncrypt(
        shared.keyTextToKeyData("aes", "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.hexToBytesArray("8CD084B7-35ECE917-E6A27079-3273B548-DA95CE63-2EB9AD13-7154F623-44C73D97"),
        false,
        true
    );

});

asyncTest("Encrypt Sync Process", function () {

    aesCbcTest.aesEncrypt(
        shared.keyTextToKeyData("aes", "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.hexToBytesArray("8CD084B7-35ECE917-E6A27079-3273B548-DA95CE63-2EB9AD13-7154F623-44C73D97"),
        true,
        true
    );

});

asyncTest("Decrypt Async", function () {

    aesCbcTest.aesDecrypt(
        shared.keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        shared.hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        false
    );
});

asyncTest("Decrypt Sync", function () {

    aesCbcTest.aesDecrypt(
        shared.keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        shared.hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false
    );

});

asyncTest("Decrypt Sync Process", function () {

    aesCbcTest.aesDecrypt(
        shared.keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        shared.hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        true
    );

});

asyncTest("Decrypt Async Process", function () {

    aesCbcTest.aesDecrypt(
        shared.keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        shared.hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        shared.toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        true
    );

});

asyncTest("128 vectors ", function () {

    var vectors = testVectorsAESCBC["AES-CBC-128"];

    expect(vectors.length * 2);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = shared.hexToBytesArray(vector.key);
        var ivBytes = shared.hexToBytesArray(vector.iv);
        var ptBytes = shared.hexToBytesArray(vector.pt);
        var ctBytes = shared.hexToBytesArray(vector.ct);

        aesCbcTest.aesRoundTrip(aesCbcTest.aesResults1, keyBytes, ptBytes, ivBytes, ctBytes, false, false);

    }

    aesCbcTest.waitAes(aesCbcTest.aesResults1, vectors.length * 2);

});

asyncTest("192 vectors ", function () {

    var vectors = testVectorsAESCBC["AES-CBC-192"];

    expect(vectors.length * 2);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = shared.hexToBytesArray(vector.key);
        var ivBytes = shared.hexToBytesArray(vector.iv);
        var ptBytes = shared.hexToBytesArray(vector.pt);
        var ctBytes = shared.hexToBytesArray(vector.ct);

        aesCbcTest.aesRoundTrip(aesCbcTest.aesResults2, keyBytes, ptBytes, ivBytes, ctBytes, false, false);

    }

    aesCbcTest.waitAes(aesCbcTest.aesResults2, vectors.length * 2);

});

asyncTest("256 vectors ", function () {

    var vectors = testVectorsAESCBC["AES-CBC-256"];

    expect(vectors.length * 2);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = shared.hexToBytesArray(vector.key);
        var ivBytes = shared.hexToBytesArray(vector.iv);
        var ptBytes = shared.hexToBytesArray(vector.pt);
        var ctBytes = shared.hexToBytesArray(vector.ct);

        aesCbcTest.aesRoundTrip(aesCbcTest.aesResults3, keyBytes, ptBytes, ivBytes, ctBytes, false, false);

    }

    aesCbcTest.waitAes(aesCbcTest.aesResults3, vectors.length * 2);

});