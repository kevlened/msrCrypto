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
/* global cryptoMath */
/* global cryptoECC */
/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */

/// <dictionary>btd,dtb,Ecdh,ecop,msrcrypto</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoEcdh = function (curve) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        e = curve,
        ecop = new cryptoECC.EllipticCurveOperatorFp(curve);

    function generateKey(privateKeyBytes) {
        /// <summary></summary>
        /// <param name="privateKeyBytes" type="Array" optional="true">
        ///     For testing purposes we allow the key bytes to be passed in
        ///     instead of randomly generated.
        /// </param>
        /// <returns type=""></returns>

        var privateKey = [],
            randomBytes = msrcryptoPseudoRandom.getBytes(
                curve.order.length * cryptoMath.DIGIT_NUM_BYTES);

        //#debug
        randomBytes = privateKeyBytes || randomBytes;
        //#enddebug

        cryptoMath.reduce(
            cryptoMath.bytesToDigits(randomBytes),
            e.order,
            privateKey);

        var publicKey = e.allocatePointStorage();

        ecop.scalarMultiply(privateKey, e.generator, publicKey);

        return {
            privateKey: {
                x: dtb(publicKey.x),
                y: dtb(publicKey.y),
                d: dtb(privateKey)
            },
            publicKey: {
                x: dtb(publicKey.x),
                y: dtb(publicKey.y)
            }
        };
    }

    function deriveBits(privateKey, publicKey, length) {

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            e, false, btd(publicKey.x), btd(publicKey.y), null, false);

        var sharedSecretPoint = e.allocatePointStorage();
        ecop.convertToJacobianForm(sharedSecretPoint);
        ecop.convertToMontgomeryForm(sharedSecretPoint);

        ecop.scalarMultiply(btd(privateKey.d), publicPoint, sharedSecretPoint);

        ecop.convertToAffineForm(sharedSecretPoint);
        ecop.convertToStandardForm(sharedSecretPoint);

        var secretBytes = cryptoMath.digitsToBytes(sharedSecretPoint.x);

        if (length && (secretBytes.length * 8) < length) {
            throw new Error("DataError");
        }

        return length ? secretBytes.slice(0, length / 8) : secretBytes;
    }

    function computePublicKey(privateKeyBytes) {

        if (!e.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(e.generator);
        }

        var publicKey = e.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(btd(privateKeyBytes), e.generator, publicKey);

        return {
            x: dtb(publicKey.x),
            y: dtb(publicKey.y)
        };
    }

    return {

        generateKey: generateKey,
        deriveBits: deriveBits,
        computePublicKey: computePublicKey
    };

};

var ecdhInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoEcdh.deriveBits = function (p) {

        var curve = cryptoECC.createCurve(p.algorithm.namedCurve.toUpperCase());

        var privateKey = p.keyData;

        var publicKey = p.additionalKeyData;

        ecdhInstance = msrcryptoEcdh(curve);

        var secretBytes = ecdhInstance.deriveBits(privateKey, publicKey, p.length);

        return secretBytes;
    };

    msrcryptoEcdh.generateKey = function (p) {

        var curve = cryptoECC.createCurve(p.algorithm.namedCurve.toUpperCase());

        ecdhInstance = msrcryptoEcdh(curve);

        var keyPairData = ecdhInstance.generateKey();

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: keyPairData.publicKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: p.keyUsage,
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: keyPairData.privateKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: p.keyUsage,
                        type: "private"
                    }
                }
            }
        };
    };

    msrcryptoEcdh.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["x", "y", "d", "crv"]);

        // If only private key data 'd' is imported, create x and y
        if (keyObject.d && (!keyObject.x || !keyObject.y)) {

            var curve = cryptoECC.createCurve(p.algorithm.namedCurve.toUpperCase());

            ecdhInstance = msrcryptoEcdh(curve);

            var publicKey = ecdhInstance.computePublicKey(keyObject.d);

            keyObject.x = publicKey.x;
            keyObject.y = publicKey.y;
        }

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: p.keyUsage,
                type: (keyObject.d) ? "private" : "public"
            }
        };
    };

    msrcryptoEcdh.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };

    };

    operations.register("importKey", "ecdh", msrcryptoEcdh.importKey);
    operations.register("exportKey", "ecdh", msrcryptoEcdh.exportKey);
    operations.register("generateKey", "ecdh", msrcryptoEcdh.generateKey);
    operations.register("deriveBits", "ecdh", msrcryptoEcdh.deriveBits);
}