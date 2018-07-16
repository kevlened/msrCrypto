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

/// <reference path="../qunit/qunit-1.15.0.js" />
/// <reference path="../dotNet/dotNetInterop.js" />
/// <reference path="../../msrcrypto.js" />
/// <reference path="SubtleTest.shared.js" />

module(".Net Interop");

var algPkcs1v15 = { name: "rSaes-pkcs1-v1_5" };

var algPkcs1v151 = { name: "rSassa-pkcs1-v1_5", hash: { name: "Sha-1" } };
var algPkcs1v15224 = { name: "rSassa-pkcs1-v1_5", hash: { name: "Sha-224" } };
var algPkcs1v15256 = { name: "rSassa-pkcs1-v1_5", hash: { name: "Sha-256" } };
var algPkcs1v15384 = { name: "rSassa-pkcs1-v1_5", hash: { name: "Sha-384" } };
var algPkcs1v15512 = { name: "rSassa-pkcs1-v1_5", hash: { name: "Sha-512" } };

var algOaep1 = { name: "rSa-oaep", hash: { name: "Sha-1" } };
var algOaep256 = { name: "rSa-oaep", hash: { name: "Sha-256" } };
var algOaep384 = { name: "rSa-oaep", hash: { name: "Sha-384" } };
var algOaep512 = { name: "rSa-oaep", hash: { name: "Sha-512" } };

var curveNames = ["p-256", "p-384"];
var hashNames = ["sha-1", "sha-256", "sha-384", "sha-512"];

// #region ECDH Tests

for (var curve in curveNames) {

    for (var hash in hashNames) {

        var curveName = curveNames[curve];
        var hashName = hashNames[hash];
        var algorithm = { name: "Ecdh", namedCurve: curveName, hash: { name: hashName } };

        asyncTest("ECDH " + curveName.toUpperCase() + " " + hashName.toUpperCase(), (function (algorithm) {

            return function () {

                ecdhTest(algorithm.namedCurve, algorithm.hash.name,
                    algorithm.namedCurve + "|" + algorithm.hash.name);

            };

        })(algorithm));
    }
}

// #endregion ECDH Tests

// #region Sign/Verify Tests

for (var curve in curveNames) {

    for (var hash in hashNames) {

        var curveName = curveNames[curve];
        var hashName = hashNames[hash];
        var algorithm = { name: "Ecdsa", namedCurve: curveName, hash: { name: hashName } };

        asyncTest("ECDSA Sign .Net/Verify JS  " + curveName.toUpperCase() + " " + hashName.toUpperCase(), (function (algorithm) {

            return function () {

                var plainText = getRandomData(1024);

                ecdsa_signNet_verifyJS(plainText, algorithm);
            };

        })(algorithm));

        asyncTest("ECDSA Sign JS/Verify .Net " + curveName.toUpperCase() + " " + hashName.toUpperCase(), (function (algorithm) {

            return function () {

                var plainText = getRandomData(1024);

                ecdsa_signJS_verifyNet(plainText, algorithm);
            };

        })(algorithm));

    }
}

var modulusSizes = [1024, 2048];
var rsaAlgorithmNames = ["rsassa-pkcs1-v1_5", "rsa-pss"];

for (var mod in modulusSizes) {

    for (var alg in rsaAlgorithmNames) {

        for (var hash in hashNames) {

            var modulus = modulusSizes[mod];
            var algorithmName = rsaAlgorithmNames[alg];
            var hashName = hashNames[hash];
            var algorithm = { name: algorithmName, hash: { name: hashName } };

            // This is an invalid combination since the size of the hash eats up all
            // the space of the digest.
            if (modulus === 1024 && algorithmName === "rsa-pss" && hashName === "sha-512") {
                continue;
            }

            asyncTest(algorithmName.toUpperCase() + " Sign .Net/Verify JS  Mod-" + modulus + " " + hashName.toUpperCase(), (function (modulus, algorithm) {

                return function () {

                    var plainText = getRandomData(maxMessageSize(modulus, algorithm.name));

                    rsa_signNet_verifyJS(plainText, modulus, algorithm);
                };

            })(modulus, algorithm));

            asyncTest(algorithmName.toUpperCase() + " Sign JS/Verify .Net  Mod-" + modulus + " " + hashName.toUpperCase(), (function (modulus, algorithm) {

                return function () {

                    var plainText = getRandomData(maxMessageSize(modulus, algorithmName));

                    rsa_signJS_verifyNet(plainText, modulus, algorithm);
                };

            })(modulus, algorithm));
        }
    }
}

// #endregion Sign/Verify Tests

// #region Encrypt/Decrypt Tests

asyncTest("Encrypt JS/Decrypt JS 1024 PKCS1v15", function () {

    var modulus = 1024;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 2048 PKCS1v15", function () {

    var modulus = 2048;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 4096 PKCS1v15", function () {

    var modulus = 4096;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 1024 PKCS1v15", function () {

    var modulus = 1024;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 2048 PKCS1v15", function () {

    var modulus = 2048;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 1024 PKCS1v15", function () {

    var modulus = 1024;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 2048 PKCS1v15", function () {

    var modulus = 2048;
    var algorithm = algPkcs1v15;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 1024 OAEP-1", function () {

    var modulus = 1024;
    var algorithm = algOaep1;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 1024 OAEP-256", function () {

    var modulus = 1024;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 1024 OAEP-384", function () {

    var modulus = 1024;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

// Cannot do this test with 1024 modulus
// The max message size is -2 because the hash result is too big
//asyncTest("Encrypt .Net/Decrypt JS 1024 OAEP-512", function () {

//    var modulus = 1024;
//    var algorithm = algOaep512;

//    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
//    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

//});

asyncTest("Encrypt .Net/Decrypt JS 2048 OAEP-1", function () {

    var modulus = 1024;
    var algorithm = algOaep1;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 2048 OAEP-256", function () {

    var modulus = 2048;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 2048 OAEP-384", function () {

    var modulus = 2048;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt .Net/Decrypt JS 2048 OAEP-512", function () {

    var modulus = 2048;
    var algorithm = algOaep512;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptNet_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 1024 OAEP-256", function () {

    var modulus = 1024;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 2048 OAEP-256", function () {

    var modulus = 2048;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 4096 OAEP-256", function () {

    var modulus = 4096;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 1024 OAEP-384", function () {

    var modulus = 1024;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 2048 OAEP-384", function () {

    var modulus = 2048;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 4096 OAEP-384", function () {

    var modulus = 4096;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 2048 OAEP-512", function () {

    var modulus = 2048;
    var algorithm = algOaep512;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt .Net 4096 OAEP-512", function () {

    var modulus = 4096;
    var algorithm = algOaep512;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptNet(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 1024 OAEP-256", function () {

    var modulus = 1024;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 2048 OAEP-256", function () {

    var modulus = 2048;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 4096 OAEP-256", function () {

    var modulus = 4096;
    var algorithm = algOaep256;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 1024 OAEP-384", function () {

    var modulus = 1024;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 2048 OAEP-384", function () {

    var modulus = 2048;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 4096 OAEP-384", function () {

    var modulus = 4096;
    var algorithm = algOaep384;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 2048 OAEP-512", function () {

    var modulus = 2048;
    var algorithm = algOaep512;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

asyncTest("Encrypt JS/Decrypt JS 4096 OAEP-512", function () {

    var modulus = 4096;
    var algorithm = algOaep512;

    var plainText = getRandomData(maxMessageSize(modulus, algorithm));
    rsa_encryptJS_DecryptJS(plainText, modulus, algorithm);

});

// #endregion Encrypt/Decrypt Tests

// #region Tests Functions

var count = 0;

function ecdsa_signNet_verifyJS(plainBytes, algorithm) {


    importDotNetEcKey(algorithm, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        var signatureBytes = dotNet.sign(algorithm.name, keyData.keyDataPrivate, plainBytes, algorithm.hash.name, algorithm.namedCurve);

        // Verify the plain-text/signature with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        verifyEcdsaJavaScript(keyData, plainBytes, signatureBytes, algorithm, verifyComplete);
    }

    // Called when the JS verify is completes. 
    function verifyComplete(keyData, verified) {

        start();

        // Check that the signature was verified
        equal(verified, true);
    }

}

function ecdsa_signJS_verifyNet(plainBytes, algorithm) {

    importDotNetEcKey(algorithm, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        // Sign the plain-text with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        signRsaJavaScript(keyData, plainBytes, algorithm, signComplete);
    }

    // Called when the JS encryption is completes. The params contain the cipherBytes and
    // key data used to encrypt.
    function signComplete(keyData, signatureBytes) {

        // Verify the signatureBytes with .Net - The public key is passed back to .Net
        // for the verification.
        var verified = dotNet.verify(algorithm.name, keyData.keyDataPublic, plainBytes, signatureBytes, algorithm.hash.name, algorithm.namedCurve);

        start();

        if (verified.error) {
            ok(false, verified.error + "\n" + verified.stackTrace);
            return;
        }

        // Check that the original plain-text matches the .Net decrypted text
        equal(verified, true, signatureBytes.join());
    }

}

function rsa_signNet_verifyJS(plainBytes, modulusSize, rsaAlg) {

    // Call .Net to generate an RSA key pair and return the result to the callback.
    importDotNetRsaKey(modulusSize, rsaAlg, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        var hashAlg = (rsaAlg === algPkcs1v15) ? null : rsaAlg.hash.name;

        // Sign the plainText with .Net - The private key is passed back to .Net
        // for the signing.
        var signatureBytes = dotNet.sign(rsaAlg.name, keyData.keyDataPrivate, plainBytes, hashAlg);

        if (signatureBytes.error) {
            start();
            ok(false, signatureBytes.error + "\n" + signatureBytes.stackTrace);
            return;
        }

        // Verify the plain-text/signature with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        verifyRsaJavaScript(keyData, plainBytes, signatureBytes, rsaAlg, verifyComplete);
    }

    // Called when the JS verify is completes. 
    function verifyComplete(keyData, verified) {

        start();

        // Check that the signature was verified
        equal(verified, true, "Mod " + modulusSize + ", alg " + rsaAlg.name + ", hash " + rsaAlg.hash.name);
    }
}

function rsa_signJS_verifyNet(plainBytes, modulusSize, rsaAlg) {

    // Call .Net to generate an RSA key pair and return the result to the callback.
    importDotNetRsaKey(modulusSize, rsaAlg, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        // Encrypt the plain-text with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        signRsaJavaScript(keyData, plainBytes, rsaAlg, signComplete);
    }

    // Called when the JS encryption is completes. The params contain the cipherBytes and
    // key data used to encrypt.
    function signComplete(keyData, signatureBytes) {

        var hashAlg = (rsaAlg === algPkcs1v15) ? null : rsaAlg.hash.name;

        // Decrypt the cipherBytes with .Net - The private key is passed back to .Net
        // for the decryption.
        var verified = dotNet.verify(rsaAlg.name, keyData.keyDataPrivate, plainBytes, signatureBytes, hashAlg);

        start();

        if (verified.error) {
            ok(false, verified.error + "\n" + verified.stackTrace);
            return;
        }

        // Check that the original plain-text matches the .Net decrypted text
        equal(verified, true, "Mod " + modulusSize + ", alg " + rsaAlg.name + ", hash " + rsaAlg.hash.name);
    }

}

function rsa_encryptJS_DecryptJS(plainBytes, modulusSize, rsaAlg) {

    // Call .Net to generate an RSA key pair and return the result to the callback.
    importDotNetRsaKey(modulusSize, rsaAlg, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        // Encrypt the plain-text with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        encryptRsaJavaScript(keyData, plainBytes, rsaAlg, encryptionComplete);
    }

    // Called when the JS encryption is completes. The params contain the cipherBytes and
    // key data used to encrypt.
    function encryptionComplete(keyData, cipherBytes) {

        // Decrypt the cipherBytes with .Net - The private key is passed back to .Net
        // for the decryption.
        var decOp = subtle.decrypt(rsaAlg, keyData.keyHandlePrivate, cipherBytes);

        decOp.oncomplete = function (e) {

            var decryptedBytes = shared.getArrayResult(e.target.result);

            start();

            // Check that the original plain-text matches the .Net decrypted text
            equal(decryptedBytes.join(), plainBytes.join(), decryptedBytes.join() + "=" + plainBytes.join());
        };
    }

}

function rsa_encryptJS_DecryptNet(plainBytes, modulusSize, rsaAlg) {

    // Call .Net to generate an RSA key pair and return the result to the callback.
    importDotNetRsaKey(modulusSize, rsaAlg, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        // Encrypt the plain-text with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        encryptRsaJavaScript(keyData, plainBytes, rsaAlg, encryptionComplete);
    }

    // Called when the JS encryption is completes. The params contain the cipherBytes and
    // key data used to encrypt.
    function encryptionComplete(keyData, cipherBytes) {

        var hashAlg = (rsaAlg === algPkcs1v15) ? null : rsaAlg.hash.name;

        // Decrypt the cipherBytes with .Net - The private key is passed back to .Net
        // for the decryption.
        var decryptedBytes = dotNet.decrypt(keyData.keyDataPrivate, cipherBytes, hashAlg);

        start();

        if (decryptedBytes.error) {
            ok(false, decryptedBytes.error + "\n" + decryptedBytes.stackTrace);
            return;
        }

        // Check that the original plain-text matches the .Net decrypted text
        equal(decryptedBytes.join(), plainBytes.join(), decryptedBytes.join() + "=" + plainBytes.join());
    }

}

function rsa_encryptNet_DecryptJS(plainBytes, modulusSize, rsaAlg) {

    // Call .Net to generate an RSA key pair and return the result to the callback.
    importDotNetRsaKey(modulusSize, rsaAlg, keyImported);

    // Called when the .Net key import is complete.
    function keyImported(keyData) {

        var hashAlg = (rsaAlg === algPkcs1v15) ? null : rsaAlg.hash.name;

        // Encrypt the plainText with .Net - The public key is passed back to .Net
        // for the encryption.
        var cipherBytes = dotNet.encrypt(keyData.keyDataPublic, plainBytes, hashAlg);

        if (cipherBytes.error) {
            start();
            ok(false, cipherBytes.error + "\n" + cipherBytes.stackTrace);
            return;
        }

        // Decrypt the cipher-text with the msrCrypto library on the client with JS
        // Using the .Net generated keys. Calls the callback when complete.
        decryptRsaJavaScript(keyData, cipherBytes, rsaAlg, decryptionComplete);
    }

    // Called when the JS decryption is completes. 
    function decryptionComplete(decryptedBytes) {

        start();

        // Check that the original plain-text matches the .Net decrypted text
        equal(decryptedBytes.join(), plainBytes.join(), decryptedBytes.join() + "=" + plainBytes.join());
    }
}

function ecdhTest(curveName, hashName, serverKeyId) {

    // Generate an ecc key pair for the client
    var keyOpGen = subtle.generateKey({ name: "Ecdh", namedCurve: curveName });

    keyOpGen.oncomplete = function (e) {
        
        var keyPair = e.target.result;

        var serverSecrect;

        shared.getKeyData(keyPair.publicKey, function (clientPublicKey) {

            // Call deriveBits on the server.  DeriveBits does a couple of things. 
            // It generates an ecc key for the server; uses the client public key
            // and server private key to compute a shared secret; returns the server
            // public key & the shared secrect to the caller.
            // The returned shared-secret is only for test purposes to compare against
            // a client generated shared-secret. 
            var result = dotNet.deriveBits(clientPublicKey, hashName);

            // The results is an Object array. The first element contains the server
            // public key; the second element contains the server computed shared
            // secret.
            var serverPublicKey = result[0];

            serverSecrect = result[1];

            // Convert the server public key to bytes.
            var keyBytes = shared.textToBytes(JSON.stringify(serverPublicKey));

            // Import the server public key into the JavaScript key store.
            var keyOpImport = subtle.importKey("Jwk", keyBytes, { name: "Ecdh", namedCurve: curveName }, true, []);

            keyOpImport.oncomplete = function (e) {

                // The imported server public key
                var serverPublicKeyHandle = e.target.result;

                // The client private key
                var clientPrivateKeyHandle = keyPair.privateKey;

                // Compute a shared secret from the server public key and the client private key
                var cryptoOp = msrCrypto.subtle.deriveBits(
                        {
                            name: "Ecdh",
                            namedCurve: curveName,
                            publicKey: serverPublicKeyHandle
                        },
                        clientPrivateKeyHandle);

                cryptoOp.oncomplete = function (e) {

                    // shared secret we computed on the client
                    var secret = shared.getArrayResult(e.target.result);

                    // CNG's ecdh will compute a secret and then hash it. So we're getting a hashed
                    // secret back from the server. We'll now hash the client generated secret to
                    // compare against the server hashed secret.
                    var hashOp = subtle.digest({ name: hashName }, secret);

                    hashOp.oncomplete = (function (serverSecrect) {

                        return function (e) {

                            // the hashed client secret
                            var clientSecret = shared.getArrayResult(e.target.result);

                            start();

                            // Verify the client secret is the same as the server secret.
                            equal(clientSecret.join(), serverSecrect.join(),
                                "Client Secret : " +
                                shared.bytesToHexString(clientSecret) + " == " +
                                "Server Secret : " +
                                shared.bytesToHexString(serverSecrect));
                        };

                    })(serverSecrect);

                }
            }

        });
    }

}

function maxMessageSize(modulusBits, algorithm) {

    var hashSizes = {
        "sha-1": 20,
        "sha-224": 28,
        "sha-256": 32,
        "sha-384": 48,
        "sha-512": 64
    }

    if (algorithm.name === "rsa-oaep") {
        // OAEP
        return (modulusBits / 8) - 2 * hashSizes[algorithm.hash.name] - 2;
    }

    // PKCS
    return (modulusBits / 8) - 11;

}

function getRandomData(maxBytes) {

    var randomBytes = new Array(Math.floor(Math.random() * (maxBytes + 1)));

    dotNet.getRandomBytes(randomBytes);

    return randomBytes;
}

function importDotNetRsaKey(modulusSize, rsaAlg, callback) {

    var keyPair = dotNet.getRsaKeyPair(modulusSize),
        keyDataPrivate = shared.textToBytes(keyPair.privateKey),
        keyDataPublic = shared.textToBytes(keyPair.publicKey),
        keyHandlePrivate,
        keyHandlePublic;

    var keyOpPrivate = subtle.importKey("Jwk", keyDataPrivate, rsaAlg, true, []);

    keyOpPrivate.oncomplete = function (e1) {

        keyHandlePrivate = e1.target.result;

        var keyOpPublic = subtle.importKey("Jwk", keyDataPublic, rsaAlg, true, []);

        keyOpPublic.oncomplete = function (e2) {

            keyHandlePublic = e2.target.result;

            var keyData = {
                keyHandlePublic: keyHandlePublic,
                keyHandlePrivate: keyHandlePrivate,
                keyDataPublic: keyPair.publicKey,
                keyDataPrivate: keyPair.privateKey
            };

            callback(keyData);
        };
    };
}

function importDotNetEcKey(rsaAlg, callback) {

    var keyPair = dotNet.getEcKeyPair(rsaAlg.namedCurve),
        keyDataPrivate = shared.textToBytes(keyPair.privateKey),
        keyDataPublic = shared.textToBytes(keyPair.publicKey),
        keyHandlePrivate,
        keyHandlePublic;

    var keyOpPrivate = subtle.importKey("Jwk", keyDataPrivate, rsaAlg, true, []);

    keyOpPrivate.oncomplete = function (e1) {

        keyHandlePrivate = e1.target.result;

        var keyOpPublic = subtle.importKey("Jwk", keyDataPublic, rsaAlg, true, []);

        keyOpPublic.oncomplete = function (e2) {

            keyHandlePublic = e2.target.result;

            var keyData = {
                keyHandlePublic: keyHandlePublic,
                keyHandlePrivate: keyHandlePrivate,
                keyDataPublic: keyPair.publicKey,
                keyDataPrivate: keyPair.privateKey
            };

            callback(keyData);
        };
    };
}

function signRsaJavaScript(keyData, plainBytes, rsaAlg, callback) {

    var encOp = subtle.sign(rsaAlg, keyData.keyHandlePrivate, plainBytes);

    encOp.oncomplete = function (e) {

        var signatureBytes = shared.getArrayResult(e.target.result);

        callback(keyData, signatureBytes);
    };

    encOp.onerror = function (e) {

        var error = e;

        start();

        ok(false, error.message);
    };
}

function verifyRsaJavaScript(keyData, plainBytes, signatureBytes, rsaAlg, callback) {

    var encOp = subtle.verify(rsaAlg, keyData.keyHandlePublic, signatureBytes, plainBytes);

    encOp.oncomplete = function (e) {

        var verified = e.target.result;

        callback(keyData, verified);
    };

    encOp.onerror = function (e) {

        var error = e;

        start();

        ok(false, error.message);
    };
}

function verifyEcdsaJavaScript(keyData, plainBytes, signatureBytes, algorithm, callback) {

    var encOp = subtle.verify(algorithm, keyData.keyHandlePublic, signatureBytes, plainBytes);

    encOp.oncomplete = function (e) {

        var verified = e.target.result;

        callback(keyData, verified);
    };

    encOp.onerror = function (e) {

        var error = e;

        start();

        ok(false, error.message);
    };
}

function encryptRsaJavaScript(keyData, plainBytes, rsaAlg, callback) {

    var encOp = subtle.encrypt(rsaAlg, keyData.keyHandlePublic, plainBytes);

    encOp.oncomplete = function (e) {

        var cipherBytes = shared.getArrayResult(e.target.result);

        callback(keyData, cipherBytes);
    };

    encOp.onerror = function (e) {

        var error = e;

        start();

        ok(false, error.message);
    };
}

function decryptRsaJavaScript(keyData, cipherBytes, rsaAlg, callback) {

    var decOp = subtle.decrypt(rsaAlg, keyData.keyHandlePrivate, cipherBytes);

    decOp.oncomplete = function (e) {

        var plainBytes = shared.getArrayResult(e.target.result);

        callback(plainBytes);
    };
}

// #endregion Tests Functions