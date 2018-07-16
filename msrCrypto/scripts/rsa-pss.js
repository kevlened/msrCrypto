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

/* global msrcryptoPseudoRandom */
/* global msrcryptoUtilities */
/* global rsaShared */

/* jshint -W016 */

/// <dictionary>emsa,rsa,Struct,utils,octect</dictionary>

/// <disable>DeclareVariablesBeforeUse, DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var rsaMode = rsaMode || {};
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>

rsaMode.pss = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        random = msrcryptoPseudoRandom;

    function emsa_pss_encode(messageBytes, /*@optional*/ saltLength, /*@optional*/ salt) {

        var emBits = (keyStruct.n.length * 8) - 1,
            emLen = Math.ceil(emBits / 8),
            /*@type(Array)*/ mHash = hashFunction.computeHash(messageBytes);

        saltLength = salt ? salt.length : saltLength || mHash.length;

        if (emLen < (mHash.length + saltLength + 2)) {
            throw new Error("encoding error");
        }

        /*@type(Array)*/ salt = salt || random.getBytes(saltLength);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [0, 0, 0, 0, 0, 0, 0, 0].concat(mHash, salt);

        var /*@type(Array)*/ h = hashFunction.computeHash(mp);

        var /*@type(Array)*/ ps = utils.getVector(emLen - salt.length - h.length - 2);

        var /*@type(Array)*/ db = ps.concat([1], salt);

        var /*@type(Array)*/ dbMask = rsaShared.mgf1(h, emLen - h.length - 1, hashFunction);

        var /*@type(Array)*/ maskedDb = utils.xorVectors(db, dbMask);

        // Set the ((8 * emLen) - emBits) of the leftmost octect in maskedDB to zero
        var mask = 0;
        for (var i = 0; i < 8 - ((8 * emLen) - emBits) ; i++) {
            mask += 1 << i;
        }
        maskedDb[0] &= mask;

        var em = maskedDb.concat(h, [0xbc]);

        return em;
    }

    function emsa_pss_verify( /*@type(Array)*/ signatureBytes,/*@type(Array)*/ messageBytes, /*@optional*/ saltLength) {

        var emBits = (keyStruct.n.length * 8) - 1;

        var emLen = Math.ceil(emBits / 8);

        var mHash = hashFunction.computeHash(messageBytes);

        var hLen = mHash.length;

        saltLength = saltLength || hLen;

        if (emLen < (hLen + saltLength + 2)) {
            return false;
        }

        var maskedDb = signatureBytes.slice(0, emLen - hLen - 1);

        var h = signatureBytes.slice(maskedDb.length, maskedDb.length + hLen);

        var dbMask = rsaShared.mgf1(h, emLen - hLen - 1, hashFunction);

        var /*@type(Array)*/ db = utils.xorVectors(maskedDb, dbMask);

        // Set the leftmost 8 * emLen - emBits of db[0] to zero
        db[0] &= 0xFF >>> (8 - ((8 * emLen) - emBits));

        // Verify the leftmost bytes are zero
        for (var i = 0; i < (emLen - hLen - saltLength - 2) ; i++) {
            if (db[i] !== 0) {
                return false;
            }
        }

        if (db[emLen - hLen - saltLength - 2] !== 0x01) {
            return false;
        }

        var salt = db.slice(-saltLength);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [0, 0, 0, 0, 0, 0, 0, 0].concat(mHash, salt);

        var hp = hashFunction.computeHash(mp);

        return utils.arraysEqual(hp, h);
    }

    return {

        sign: function (messageBytes, /*@optional*/ saltLength, /*@optional*/ salt) {
            return emsa_pss_encode(messageBytes, saltLength, salt);
        },

        verify: function (signatureBytes, messageBytes, /*@optional*/ saltLength) {
            return emsa_pss_verify(signatureBytes, messageBytes, saltLength);
        }
    };
};