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

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */
/* global operations */
/* global msrcryptoUtilities */
/* global msrcryptoBlockCipher */
/* jshint -W016 */ /* allows bitwise operators */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="operations.js" />
/// <reference path="jwk.js" />
/// <reference path="aes.js" />

/// <dictionary>
///     Gcm,gcrt,Gctr,ghash,icb,msrcrypto,Subkey,utils
/// </dictionary>

/// <disable>IncorrectNumberOfArguments</disable>

/// #endregion JSCop/JsHint

var msrcryptoGcm = function (/*@type(msrcryptoAes)*/ blockCipher) {

    var utils = msrcryptoUtilities;

    var /*@type(Array)*/ mBuffer = [],
        /*@type(Array)*/ mIvBytes,
        /*@type(Array)*/ mAdditionalBytes,
        /*@type(Number)*/ mTagLength,
        /*@type(Array)*/ mJ0,
        /*@type(Array)*/ mJ0inc,
        /*@type(Array)*/ mH = blockCipher.encrypt(utils.getVector(16)),
        /*@type(Array)*/ mGHashState = utils.getVector(16),
        /*@type(Array)*/ mGHashBuffer = [],
        /*@type(Array)*/ mCipherText = [],
        /*@type(Array)*/ mGctrCb,
        /*@type(Number)*/ mBytesProcessed = 0;

    function ghash(/*@type(Array)*/hashSubkey, /*@type(Array)*/dataBytes) {

        var blockCount = Math.floor(dataBytes.length / 16),
            dataBlock;

        for (var i = 0; i < blockCount; i++) {
            dataBlock = dataBytes.slice(i * 16, i * 16 + 16);
            mGHashState = blockMultiplication(utils.xorVectors(mGHashState, dataBlock), hashSubkey);
        }

        mGHashBuffer = dataBytes.slice(blockCount * 16);

        return mGHashState;
    }

    function finishGHash() {

        var u = 16 * Math.ceil(mBytesProcessed / 16) - mBytesProcessed;

        var lenA = numberTo8Bytes(mAdditionalBytes.length * 8),
            lenC = numberTo8Bytes(mBytesProcessed * 8);

        var p = mGHashBuffer.concat(utils.getVector(u)).concat(lenA).concat(lenC);

        return ghash(mH, p);

    }

    function blockMultiplication(/*@type(Array)*/blockX, /*@type(Array)*/blockY) {

        var z = utils.getVector(16),
            v = blockY.slice(),
            r = [0xe1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            bit;

        for (var i = 0; i < 128; i++) {
            bit = getBit(blockX, i);

            if (bit === 1) {
                z = utils.xorVectors(z, v);
            }

            if (v[15] & 1) {
                shiftRight(v);
                v = utils.xorVectors(v, r);
            } else {
                shiftRight(v);
            }
        }

        return z;
    }

    function shiftRight(/*@type(Array)*/dataBytes) {

        for (var i = dataBytes.length - 1; i > 0; i--) {
            dataBytes[i] = ((dataBytes[i - 1] & 1) << 7) | (dataBytes[i] >>> 1);
        }
        dataBytes[0] = dataBytes[0] >>> 1;

        return dataBytes;
    }

    function getBit(/*@type(Array)*/byteArray, bitNumber) {
        var byteIndex = Math.floor(bitNumber / 8);
        return (byteArray[byteIndex] >> (7 - (bitNumber % 8))) & 1;
    }

    function inc(/*@type(Array)*/dataBytes) {

        var carry = 256;
        for (var i = 1; i <= 4; i++) {
            carry = (carry >>> 8) + dataBytes[dataBytes.length - i];
            dataBytes[dataBytes.length - i] = carry & 255;
        }

        return dataBytes;
    }

    function gctr(/*@type(Array)*/icb, /*@type(Array)*/dataBytes) {

        var blockCount = Math.ceil(dataBytes.length / 16),
            dataBlock,
            result = [];

        // We copy icb the first time gctr is called
        if (mGctrCb !== icb) {
            mGctrCb = icb.slice();
        }

        for (var block = 0; block < blockCount; block++) {

            dataBlock = dataBytes.slice(block * 16, block * 16 + 16);

            // The block cipher alters the input array, so we pass a copy.
            var e = blockCipher.encrypt(mGctrCb.slice());

            result = result.concat(utils.xorVectors(dataBlock, e));

            mGctrCb = inc(mGctrCb);
        }

        return result;
    }

    function numberTo8Bytes(number) {
        return [
            0, 0, 0, 0,
            (number >>> 24) & 255,
            (number >>> 16) & 255,
            (number >>> 8) & 255,
            number & 255
        ];
    }

    function padBlocks(/*@type(Array)*/dataBytes) {
        var padLen = 16 * Math.ceil(mAdditionalBytes.length / 16) - mAdditionalBytes.length;
        return dataBytes.concat(utils.getVector(padLen));
    }

    function clearState() {
        mBytesProcessed = 0;
        mBuffer = [];
        mCipherText = [];
        mGHashState = utils.getVector(16);
        mGHashBuffer = [];
        mGctrCb = mIvBytes = mAdditionalBytes = null;
    }

    function init(/*@type(Array)*/ivBytes, /*@type(Array)*/additionalBytes, tagLength) {

        mAdditionalBytes = additionalBytes || [];

        mTagLength = isNaN(tagLength) ? 128 : tagLength;
        if (mTagLength % 8 !== 0) {
            throw new Error("DataError");
        }

        mIvBytes = ivBytes;

        if (mIvBytes.length === 12) {
            mJ0 = mIvBytes.concat([0, 0, 0, 1]);

        } else {
            var l = 16 * Math.ceil(mIvBytes.length / 16) - mIvBytes.length;

            mJ0 = ghash(mH,
                    mIvBytes
                    .concat(utils.getVector(l + 8))
                    .concat(numberTo8Bytes(mIvBytes.length * 8)));

            // Reset the ghash state so we don't affect the encrypt/decrypt ghash
            mGHashState = utils.getVector(16);
        }

        mJ0inc = inc(mJ0.slice());

        ghash(mH, padBlocks(mAdditionalBytes));
    }

    function encrypt(/*@type(Array)*/plainBytes) {

        mBytesProcessed = plainBytes.length;

        var c = gctr(mJ0inc, plainBytes);

        ghash(mH, c);

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        clearState();

        return c.slice().concat(t);
    }

    function decrypt(/*@type(Array)*/cipherBytes, /*@type(Array)*/tagBytes) {

        mBytesProcessed = cipherBytes.length;

        var p = gctr(mJ0inc, cipherBytes);

        ghash(mH, cipherBytes);

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        clearState();

        if (utils.arraysEqual(t, tagBytes)) {
            return p;
        } else {
            return null;
        }
    }

    function processEncrypt(/*@type(Array)*/plainBytes) {

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(plainBytes);

        // Get a run of full blocks
        var fullBlocks = mBuffer.slice(0, Math.floor(mBuffer.length / 16) * 16);

        // Keep track of the total plain bytes processed
        mBytesProcessed += fullBlocks.length;

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(fullBlocks.length);

        // Process the full block with gctr - gctr maintains it's own state
        var c = gctr(mGctrCb || mJ0inc, fullBlocks);

        mCipherText = mCipherText.concat(c);

        // Process the returned blocks from gcrt
        ghash(mH, c);
    }

    function processDecrypt(/*@type(Array)*/cipherBytes) {

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(cipherBytes);

        // Get a run of full blocks.
        // We leave enough data on the end so we don't process the tag.
        var fullBlocks = mBuffer.slice(0, Math.floor((mBuffer.length - mTagLength / 8) / 16) * 16);

        // Keep track of the total plain bytes processed
        mBytesProcessed += fullBlocks.length;

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(fullBlocks.length);

        // Process the full block with gctr - gctr maintains it's own state
        var c = gctr(mGctrCb || mJ0inc, fullBlocks);

        mCipherText = mCipherText.concat(c);

        // Process the returned blocks from gcrt
        ghash(mH, fullBlocks);
    }

    function finishEncrypt() {

        var c = gctr(mGctrCb, mBuffer);

        mCipherText = mCipherText.concat(c);

        mBytesProcessed += mBuffer.length;

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        var result = mCipherText.slice().concat(t);

        clearState();

        return result;
    }

    function finishDecrypt() {

        var tagLength = Math.floor(mTagLength / 8);

        var tagBytes = mBuffer.slice( -tagLength);

        mBuffer = mBuffer.slice(0, mBuffer.length - tagLength);

        var c = gctr(mGctrCb, mBuffer);

        mCipherText = mCipherText.concat(c);

        mBytesProcessed += mBuffer.length;

        var s = finishGHash();

        var t = gctr(mJ0, s).slice(0, mTagLength / 8);

        var result = mCipherText.slice();

        clearState();

        if (utils.arraysEqual(t, tagBytes)) {
            return result;
        } else {
            throw new Error("OperationError");
        }
    }

    return {
        init: init,
        encrypt: encrypt,
        decrypt: decrypt,
        processEncrypt: processEncrypt,
        processDecrypt: processDecrypt,
        finishEncrypt: finishEncrypt,
        finishDecrypt: finishDecrypt
    };

};

var gcm;

if (typeof operations !== "undefined") {

    msrcryptoGcm.encrypt = function ( /*@dynamic*/ p) {

        var result;

        if (!gcm) {
            gcm = msrcryptoGcm(msrcryptoBlockCipher.aes(p.keyData));
            gcm.init(p.algorithm.iv, p.algorithm.additionalData, p.algorithm.tagLength);
        }

        if (p.operationSubType === "process") {
            gcm.processEncrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = gcm.finishEncrypt();
            gcm = null;
            return result;
        }

        result = gcm.encrypt(p.buffer);
        gcm = null;
        return result;
    };

    msrcryptoGcm.decrypt = function ( /*@dynamic*/ p) {

        var result;

        if (!gcm) {
            gcm = msrcryptoGcm(msrcryptoBlockCipher.aes(p.keyData));
            gcm.init(p.algorithm.iv, p.algorithm.additionalData, p.algorithm.tagLength);
        }

        if (p.operationSubType === "process") {
            gcm.processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
             result = gcm.finishDecrypt();
            gcm = null;
            return result;
        }

        var tagLength = Math.floor(p.algorithm.tagLength / 8);
        var cipherBytes = p.buffer.slice(0, p.buffer.length - tagLength);
        var tagBytes = p.buffer.slice( -tagLength);

        result = gcm.decrypt(cipherBytes, tagBytes);
        gcm = null;
        return result;
    };

    msrcryptoGcm.generateKey = function ( /*@dynamic*/ p) {

        if (p.algorithm.length % 8 !== 0) {
            throw new Error();
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoGcm.importKey = function ( /*@dynamic*/ p) {

        var /*@dynamic*/ keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoGcm.exportKey = function ( /*@dynamic*/ p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "aes-gcm", msrcryptoGcm.importKey);
    operations.register("exportKey", "aes-gcm", msrcryptoGcm.exportKey);
    operations.register("generateKey", "aes-gcm", msrcryptoGcm.generateKey);
    operations.register("encrypt", "aes-gcm", msrcryptoGcm.encrypt);
    operations.register("decrypt", "aes-gcm", msrcryptoGcm.decrypt);
}