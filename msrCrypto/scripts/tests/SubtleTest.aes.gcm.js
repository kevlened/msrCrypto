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
/// <reference path="testVectors/tv_aes_gcm.js" />

var aesGcmTest = {

    aesResults1: [],
    aesResults2: [],
    aesResults3: [],

    splitResult: function (cipherBytes, tagLengthInBytes) {

        var cipherBytesArray = shared.getArrayResult(cipherBytes);

        return {
            tagBytes: cipherBytesArray.slice(-(tagLengthInBytes)),
            cipherBytes: cipherBytesArray.slice(0, cipherBytesArray.length - tagLengthInBytes)
        };
    },

    waitAes: function (array, length) {
        if (array.length >= length) {
            start();
            for (var i = 0; i < length; i++) {
                equal(shared.bytesToHexString(array[i].result),
                      shared.bytesToHexString(array[i].expected),
                      array[i].tag);
            }

        } else {
            setTimeout(
                function () {
                    aesGcmTest.waitAes(array, length);
                }, 100);
        }
    },

    aesComplete: function (resultStorageArray, encryptionResult, expected) {

        return function (e) {
            var decryptedBytes = shared.getArrayResult(e);

            resultStorageArray.push({
                result: decryptedBytes,
                expected: expected.plainBytes,
                tag: "Decrypted: " + shared.bytesToHexString(decryptedBytes) + " | " +
                     "Plain: " + shared.bytesToHexString(expected.plainBytes)
            });

            resultStorageArray.push({
                result: encryptionResult.cipherBytes,
                expected: expected.cipherBytes,
                tag: "Encrypted: " + shared.bytesToHexString(expected.cipherBytes) + " | " +
                     "Expected: " + shared.bytesToHexString(encryptionResult.cipherBytes)
            });

            resultStorageArray.push({
                result: encryptionResult.tagBytes,
                expected: expected.tagBytes,
                tag: "Tag: " + shared.bytesToHexString(encryptionResult.tagBytes) + " | " +
                     "Expected: " + shared.bytesToHexString(expected.tagBytes)
            });
        };

    },

    aesEncryptionComplete: function (expectedCipher, expectedTag, algorithm) {
        return function (e) {
            start();

            var result = shared.getArrayResult(e);

            var tagLength = (algorithm.tagLength || 128) / 8;

            var cipherBytes = result.slice(0, result.length - tagLength);

            var tagBytes = result.slice(-tagLength);

            var cipherHex = shared.bytesToHexString(cipherBytes);

            var expectedCipherHex = shared.bytesToHexString(expectedCipher);

            var tagHex = shared.bytesToHexString(tagBytes);

            var expectedTagHex = shared.bytesToHexString(expectedTag);

            equal(cipherHex, expectedCipherHex, "should be " + expectedCipherHex);
            equal(tagHex, expectedTagHex, "should be " + expectedTagHex);
        };
    },

    aesDecryptionComplete: function (expectedPlain) {
        return function (e) {
            start();

            var cipherBytes = shared.getArrayResult(e);

            var plainHex = shared.bytesToHexString(cipherBytes);

            var expectedPlainHex = shared.bytesToHexString(expectedPlain);

            equal(plainHex, expectedPlainHex, "should be " + expectedPlainHex);
        };
    },

    aesEncrypt: function (keyBytes, dataBytes, ivBytes, additionalDataBytes, tagLength, expectedBytes, expectedTag, sync) {

        subtle.forceSync = sync;

        shared.importKey("aes-gcm", keyBytes, function (key) {

            var algorithm = {
                name: "Aes-GCM",
                iv: ivBytes,
                tagLength: tagLength
            }

            // Microsoft Edge throws an error if additionalBytes is an empty buffer
            if (additionalDataBytes.length > 0) {
                algorithm.additionalData = additionalDataBytes;
            }

            subtle.encrypt(algorithm, key, dataBytes).then(
                aesGcmTest.aesEncryptionComplete(expectedBytes, expectedTag, algorithm),
                shared.error()
            );

        }, shared.error("aesEncrypt"));

    },

    aesDecrypt: function (keyBytes, encryptedBytes, tagBytes, ivBytes, additionalDataBytes, tagLength, expectedBytes, sync) {

        subtle.forceSync = sync;

        shared.importKey("aes-gcm", keyBytes, function (key) {

            var algorithm = {
                name: "Aes-GCM",
                iv: ivBytes,
                tagLength: tagLength
            }

            // Microsoft Edge throws an error if additionalBytes is an empty buffer
            if (additionalDataBytes.length > 0) {
                algorithm.additionalData = additionalDataBytes;
            }

            encryptedBytes = shared.toSupportedArray(encryptedBytes.concat(tagBytes));

            subtle.decrypt(algorithm, key, encryptedBytes).then(
                aesGcmTest.aesDecryptionComplete(expectedBytes),
                shared.error()
            );

        }, shared.error());

    },

    aesRoundTrip: function (resultStorageArray, keyBytes, plainBytes, addBytes, ivBytes, expected, sync) {

        var cryptoOpEnc, cryptoOpDec;

        subtle.forceSync = sync;

        var jwkKeyString = shared.toBase64(keyBytes);
        jwkKeyString = jwkKeyString.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        jwkKeyString = shared.keyTextToKeyData("aes", jwkKeyString);

        shared.importKey("aes-gcm", jwkKeyString, function (key) {

            var algorithm = {
                name: "Aes-GCM",
                iv: ivBytes
            }

            // If there is not additional data, add the optional empty array to the alg object half the time
            // Microsoft Edge throws an error if additionalBytes is an empty buffer
            if (addBytes.length > 0) {
                algorithm.additionalData = addBytes;
            }

            algorithm.tagLength = expected.tagBytes.length * 8;

            subtle.encrypt(algorithm, key, plainBytes).then(

                function (result) {

                    var cipherPlusTagResult = shared.toSupportedArray(result);

                    var encryptionResult = aesGcmTest.splitResult(result, expected.tagBytes.length);

                    subtle.decrypt(algorithm, key, cipherPlusTagResult).then(
                        aesGcmTest.aesComplete(resultStorageArray, encryptionResult, expected),
                        shared.error()
                        );
                },

                function (error) {

                    var a = error;
                }
            );

        }, shared.error());

    },

    aesGenerateKey: function (keySize, sync) {

        expect(4);

        var aesKey = null;

        subtle.forceSync = sync;

        subtle.generateKey({ name: "Aes-GCM", length: keySize }, true, ['encrypt']).then(

            function (result) {

                 aesKey = result;


                 subtle.exportKey("jwk", aesKey, { name: "Aes-GCM" }, true, ["encrypt"]).then(
                     (function (key) {
                         return function (keyObject) {
                             
                             keyBytes = Array.apply(null, shared.base64UrlToBytes(keyObject.k));

                             start();

                             equal(key.type, "secret", "secret key type");
                             equal(key.algorithm.name, "AES-GCM", "AES-GCM algorithm name");

                             equal(keyBytes.length, keySize / 8, "expected number of bytes: " + keyBytes.join());
                             equal(keyObject.kty, "oct", "kty=oct");

                             equal(keyObject.alg, "A" + keySize + "GCM", "expected alg " + keyObject.alg);
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

    }


}

module("AES-GCM");


for (var i = 0; i < 2; i++) {

    for (var j = 0; j < 2; j++) {

        var process = (j === 1);
        var sync = (i === 1);

        var syncLable = sync ? " Sync" : " Async";
        var processLable = process ? " Process" : " ";

        asyncTest("Encrypt" + syncLable + processLable, function () {

            aesGcmTest.aesEncrypt(

                // Key
                shared.keyTextToKeyData("aes", shared.hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // PlainText
                shared.toSupportedArray(shared.hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")),

                // IV
                shared.toSupportedArray(shared.hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                shared.toSupportedArray([]),

                // TagLength
                128,

                // Expected Cipher
                shared.hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985 "),

                // Expected Tag
                shared.hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4"),

                // Sync
                sync,

                // Process
                process
            );

        });

        asyncTest("Decrypt" + syncLable + processLable, function () {

            aesGcmTest.aesDecrypt(

                // Key
                shared.keyTextToKeyData("aes", shared.hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // Cipher
                shared.hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),

                // Tag
                shared.hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4"),

                // IV
                shared.toSupportedArray(shared.hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                shared.toSupportedArray([]),

                // TagLength
                128,

                // Expected Plain
                shared.hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255 "),

                // Sync
                sync,

                // Process
                process

            );
        });

        asyncTest("Encrypt " + syncLable + processLable, function () {

            aesGcmTest.aesEncrypt(

                // Key
                shared.keyTextToKeyData("aes", shared.hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // PlainText
                shared.toSupportedArray(shared.hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")),

                // IV
                shared.toSupportedArray(shared.hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                shared.toSupportedArray([]),

                // TagLength
                128,

                // Expected Cipher
                shared.hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985 "),

                // Expected Tag
                shared.hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4"),

                // Sync
                sync,

                // Process
                process
            );

        });

        asyncTest("Decrypt " + syncLable + processLable, function () {

            aesGcmTest.aesDecrypt(

                // Key
                shared.keyTextToKeyData("aes", shared.hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // Cipher
                shared.hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),

                // Tag
                shared.hexToBytes("4d5c2af327cd64a62cf35abd2b"),

                // IV
                shared.toSupportedArray(shared.hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                shared.toSupportedArray([]),

                // TagLength
                104,

                // Expected Plain
                shared.hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255 "),

                // Sync
                sync,

                // Process
                process

            );
        });

    }
}


asyncTest("128 vectors ", function () {

    var vectors = testVectorsAESGCM["AES-128-GCM"];

    expect(vectors.length * 3);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = shared.hexToBytesArray(vector.key);
        var ivBytes = shared.hexToBytesArray(vector.iv);
        var ptBytes = shared.hexToBytesArray(vector.pt);
        var addBytes = shared.hexToBytesArray(vector.add);

        var expected = {
            tagBytes: shared.hexToBytesArray(vector.tag),
            cipherBytes: shared.hexToBytesArray(vector.ct),
            plainBytes: ptBytes
        }

        aesGcmTest.aesRoundTrip(aesGcmTest.aesResults1, keyBytes, ptBytes, addBytes, ivBytes, expected, false, false);

    }

    aesGcmTest.waitAes(aesGcmTest.aesResults1, vectors.length * 3);

});

asyncTest("192 vectors ", function () {

    var vectors = testVectorsAESGCM["AES-192-GCM"];

    expect(vectors.length * 3);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = shared.hexToBytesArray(vector.key);
        var ivBytes = shared.hexToBytesArray(vector.iv);
        var ptBytes = shared.hexToBytesArray(vector.pt);
        var addBytes = shared.hexToBytesArray(vector.add);

        var expected = {
            tagBytes: shared.hexToBytesArray(vector.tag),
            cipherBytes: shared.hexToBytesArray(vector.ct),
            plainBytes: ptBytes
        }

        aesGcmTest.aesRoundTrip(aesGcmTest.aesResults2, keyBytes, ptBytes, addBytes, ivBytes, expected, false, false);

    }

    aesGcmTest.waitAes(aesGcmTest.aesResults2, vectors.length * 3);

});

asyncTest("256 vectors ", function () {

    var vectors = testVectorsAESGCM["AES-256-GCM"];

    expect(vectors.length * 3);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = shared.hexToBytesArray(vector.key);
        var ivBytes = shared.hexToBytesArray(vector.iv);
        var ptBytes = shared.hexToBytesArray(vector.pt);
        var addBytes = shared.hexToBytesArray(vector.add);

        var expected = {
            tagBytes: shared.hexToBytesArray(vector.tag),
            cipherBytes: shared.hexToBytesArray(vector.ct),
            plainBytes: ptBytes
        }

        aesGcmTest.aesRoundTrip(aesGcmTest.aesResults3, keyBytes, ptBytes, addBytes, ivBytes, expected, false, false);

    }

    aesGcmTest.waitAes(aesGcmTest.aesResults3, vectors.length * 3);

});