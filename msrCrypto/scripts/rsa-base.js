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

/* global cryptoMath */
/* global msrcryptoUtilities */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="cryptoMath.js " />

/// <dictionary>mgf,rsa,Struct,utils</dictionary>

/// <disable>DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoRsaBase = function (keyStruct) {

    var utils = msrcryptoUtilities,
        keyIsPrivate = keyStruct.hasOwnProperty("n") && keyStruct.hasOwnProperty("d"),
        keyIsCrt = keyStruct.hasOwnProperty("p") && keyStruct.hasOwnProperty("q"),
        modulusLength = keyStruct.n.length;

    function toBytes(digits) {

        var bytes = cryptoMath.digitsToBytes(digits);

        // Add leading zeros until the message is the proper length.
        utils.padFront(bytes, 0, modulusLength);

        return bytes;
    }

    function /*@type(Bytes)*/ modExp(/*@type(Bytes)*/ dataBytes, /*@type(Bytes)*/ expBytes,/*@type(Bytes)*/  modulusBytes) {
        /// <returns type="Array">Result in a digit array.</returns>
        var exponent = cryptoMath.bytesToDigits(expBytes);

        var group = cryptoMath.IntegerGroup(modulusBytes);
        var base = group.createElementFromBytes(dataBytes);
        var result = group.modexp(base, exponent);

        return result.m_digits;
    }

    function decryptModExp(cipherBytes) {

        var resultElement = modExp(cipherBytes, keyStruct.d, keyStruct.n);

        return toBytes(resultElement);
    }

    function decryptCrt(cipherBytes) {

        var p = keyStruct.p,
            q = keyStruct.q,
            dp = keyStruct.dp,
            dq = keyStruct.dq,
            invQ = keyStruct.qi,
            pDigits = cryptoMath.bytesToDigits(p),
            qDigits = cryptoMath.bytesToDigits(q),
            temp = new Array(pDigits.length + qDigits.length),
            m1Digits = new Array(pDigits.length + 1),
            m2Digits = new Array(qDigits.length + 1),
            cDigits = cryptoMath.bytesToDigits(cipherBytes);

        // 'm1' = (c mod p)^dP mod p
        cryptoMath.reduce(cDigits, pDigits, temp);
        cryptoMath.modExp(temp, cryptoMath.bytesToDigits(dp), pDigits, m1Digits);

        // 'm2' = (c mod q)^dQ mod q
        cryptoMath.reduce(cDigits, qDigits, temp);
        cryptoMath.modExp(temp, cryptoMath.bytesToDigits(dq), qDigits, m2Digits);

        // 'diff' = (m1 - m2). Compute as follows to have |m1 - m2|.
        //      m1 - m2     if m1>=m2.
        //      m2 - m1     if m1<m2.
        // Correct the sign after modular multiplication by qInv by subtracting the product from p.
        var carry = cryptoMath.subtract(m1Digits, m2Digits, temp);
        if (carry !== 0) {
            cryptoMath.subtract(m2Digits, m1Digits, temp);
        }

        // 'h' = (m1 - m2)^qInv mod p
        cryptoMath.modMul(temp, cryptoMath.bytesToDigits(invQ), pDigits, cDigits);
        if (carry !== 0) {
            cryptoMath.subtract(pDigits, cDigits, cDigits);
        }

        // 'm2' + q*h
        cryptoMath.multiply(cDigits, qDigits, temp);
        cryptoMath.add(m2Digits, temp, m1Digits);

        return toBytes(m1Digits);
    }

    return {

        encrypt: function (messageBytes) {

            return toBytes(modExp(messageBytes, keyStruct.e, keyStruct.n));

        },

        decrypt: function (cipherBytes) {

            if (keyIsCrt) {
                return decryptCrt(cipherBytes);
            }

            if (keyIsPrivate) {
                return decryptModExp(cipherBytes);
            }

            throw new Error("missing private key");
        }
    };

};

var rsaShared = {

    mgf1: function (seedBytes, maskLen, hashFunction) {

        var t = [], bytes, hash, counter,
            hashByteLen = hashFunction.hashLen / 8;

        for (counter = 0; counter <= Math.floor(maskLen / hashByteLen) ; counter += 1) {

            bytes = [counter >>> 24 & 0xff,
                    counter >>> 16 & 0xff,
                    counter >>> 8 & 0xff,
                    counter & 0xff];

            hash = hashFunction.computeHash(seedBytes.concat(bytes));

            t = t.concat(hash);
        }

        return t.slice(0, maskLen);
    },

    checkMessageVsMaxHash: function (messageBytes, hashFunction) {

        // The max array size in JS is 2^32-1
        if (messageBytes.length > (hashFunction.maxMessageSize || 0xFFFFFFFF)) {
            throw new Error("message too long");
        }

        return;
    }

};