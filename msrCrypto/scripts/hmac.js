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

/// #region JSCop/JsHint

/* global operations */
/* global msrcryptoSha256 */
/* global msrcryptoSha512 */
/* global msrcryptoJwk */
/* global msrcryptoPseudoRandom */
/* jshint -W016 */

/// <reference path="sha256.js" />
/// <reference path="sha512.js" />
/// <reference path="operations.js" />
/// <reference path="random.js" />
/// <reference path="jwk.js" />

/// <dictionary>Hmac,ipad,msrcrypto,opad,sha,xor</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoHmac = (function () {

    var sha256,
        sha512,
        sha1;

    if (typeof msrcryptoSha256 !== "undefined") {
        sha256 = msrcryptoSha256;
    }

    if (typeof msrcryptoSha512 !== "undefined") {
        sha512 = msrcryptoSha512;
    }

    if (typeof msrcryptoSha1 !== "undefined") {
        sha1 = msrcryptoSha1;
    }

    var /*@dynamic*/ hashFunction;
    var blockSize;
    var keyBytes;

    var ipad;
    var opad;

    function xorArrays(array1, array2) {
        var newArray = new Array(array1);
        for (var i = 0 ; i < array1.length; i++) {
            newArray[i] = array1[i] ^ array2[i];
        }
        return newArray;
    }

    // Returns a new Array with zeroes padded on the end
    function padZeros(bytes, paddedLength) {
        var paddedArray = bytes.slice();
        for (var i = bytes.length ; i < paddedLength; i++) {
            paddedArray.push(0);
        }
        return paddedArray;
    }
    
    function padKey() {

        if (keyBytes.length === blockSize) {
            return keyBytes;
        }

        if (keyBytes.length > blockSize) {
            return padZeros(hashFunction.computeHash(keyBytes), blockSize);
        }

        // If keyBytes.length < blockSize
        return padZeros(keyBytes, blockSize);

    }

    var paddedKey = null;
    var keyXorOpad;

    function processHmac(messageBytes) {

        var keyXorIpad;
        var k0IpadText;

        // If this is the first process call, do some initial computations
        if (!paddedKey) {
            ipad = new Array(blockSize);
            opad = new Array(blockSize);
            for (var i = 0; i < blockSize; i++) { ipad[i] = 0x36; opad[i] = 0x5c; }

            paddedKey = padKey();
            keyXorIpad = xorArrays(paddedKey, ipad);
            keyXorOpad = xorArrays(paddedKey, opad);
            k0IpadText = keyXorIpad.concat(messageBytes);
            hashFunction.process(k0IpadText);

            // Subsequent process calls just add to the hash
        } else {

            hashFunction.process(messageBytes);
        }

        return;
    }

    function finishHmac() {

        var hashK0IpadText = hashFunction.finish();

        var k0IpadK0OpadText = keyXorOpad.concat(hashK0IpadText);

        return hashFunction.computeHash(k0IpadK0OpadText);
    }

    function clearState() {
        keyBytes = null;
        hashFunction = null;
        paddedKey = null;
    }

    function selectHashAlgorithm(hashAlgorithmName) {

        switch (hashAlgorithmName.toLowerCase()) {

            case "sha-1":
                if (sha1 === undefined) {
                    throw new Error("Sha1 object not found");
                }
                hashFunction = sha1.sha1;
                blockSize = 64;
                break;

            case "sha-224":
                hashFunction = sha256.sha224;
                blockSize = 64;
                break;

            case "sha-256":
                hashFunction = sha256.sha256;
                blockSize = 64;
                break;

            case "sha-384":
                if (sha512 === undefined) {
                    throw new Error("Sha512 object not found");
                }
                hashFunction = sha512.sha384;
                blockSize = 128;
                break;

            case "sha-512":
                if (sha512 === undefined) {
                    throw new Error("Sha512 object not found");
                }
                hashFunction = sha512.sha512;
                blockSize = 128;
                break;

            default:
                throw new Error("unsupported hash alorithm (sha-224, sha-256, sha-384, sha-512)");
        }

    }

    return {

        computeHmac: function (dataBytes, key, hashAlgorithm) {
            /// <summary>Computes the HMAC</summary>
            /// <param name="dataBytes" type="Array">Data to MAC</param>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>
            /// <returns type="Array">Returns an array of bytes as the HMAC</returns>

            keyBytes = key;

            selectHashAlgorithm(hashAlgorithm);

            processHmac(dataBytes);

            var result = finishHmac();

            clearState();

            return result;
        },

        process: function (dataBytes, key, hashAlgorithm) {
            /// <summary>Computes a partial HMAC to be followed by subsequent process calls or finish()</summary>
            /// <param name="dataBytes" type="Array">Data to MAC</param>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>

            if (!hashFunction) {
                keyBytes = key;
                selectHashAlgorithm(hashAlgorithm);
            }

            processHmac(dataBytes);
        },

        finish: function (key, hashAlgorithm) {
            /// <summary>Computes the final HMAC upon partial computations from previous process() calls.</summary>
            /// <param name="key" type="Array">Array of bytes for key</param>
            /// <param name="hashAlgorithm" type="String">sha-224, sha-256, sha-384, sha-512 (default sha-256)</param>
            /// <returns type="Array">Returns an array of bytes as the HMAC</returns>

            // Finish could be called before any processing. We'll return the hmac
            // of an empty buffer.
            if (!hashFunction) {
                keyBytes = key;
                selectHashAlgorithm(hashAlgorithm);
                processHmac([]);
            }

            var result = finishHmac();
            clearState();
            return result;
        }

    };
})();

if (typeof operations !== "undefined") {

    msrcryptoHmac.signHmac = function (p) {

        var hashName = p.algorithm.hash.name;

        if (p.operationSubType === "process") {
            msrcryptoHmac.process(p.buffer, p.keyData, hashName);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoHmac.finish(p.keyData, hashName);
        }

        return msrcryptoHmac.computeHmac(p.buffer, p.keyData, hashName);
    };

    msrcryptoHmac.verifyHmac = function (p) {

        var hashName = p.algorithm.hash.name;

        if (p.operationSubType === "process") {
            msrcryptoHmac.process(p.buffer, p.keyData, hashName);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoUtilities.arraysEqual(msrcryptoHmac.finish(p.keyData, hashName), p.signature);
        }

        return msrcryptoUtilities.arraysEqual(msrcryptoHmac.computeHmac(p.buffer, p.keyData, hashName), p.signature);
    };

    msrcryptoHmac.generateKey = function (p) {

        var keyLength = p.algorithm.length;

        var defaultKeyLengths = { "sha-256": 32, "sha-384": 48, "sha-512": 64 };

        if (!keyLength) {
            keyLength = defaultKeyLengths[p.algorithm.hash.name.toLowerCase()];
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(keyLength),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoHmac.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);

        keyObject.alg = keyObject.alg.replace("HS", "sha-");

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: {
                algorithm: { name: "hmac", hash: { name: keyObject.alg } },
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: "secret"
            }
        };

    };

    msrcryptoHmac.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "hmac", msrcryptoHmac.importKey);
    operations.register("exportKey", "hmac", msrcryptoHmac.exportKey);
    operations.register("generateKey", "hmac", msrcryptoHmac.generateKey);
    operations.register("sign", "hmac", msrcryptoHmac.signHmac);
    operations.register("verify", "hmac", msrcryptoHmac.verifyHmac);
}