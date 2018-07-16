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

/* global shared */

/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.15.0.js" />
/// <reference path="testVectors/tv_aes.js" />
/// <reference path="SubtleTest.shared.js" />

/// #endregion JSCop/JsHint

module("KDF");

asyncTest("Hmac 256 -> Aes 1024", function () {

    var algorithm = {
        name: "Concat",
        hash: { name: "Sha-256" },
        algorithmId: shared.toSupportedArray([1, 2, 3, 4, 5, 6]),
        partyUInfo: shared.toSupportedArray([1, 2, 3, 4, 5, 6]),
        partyVInfo: shared.toSupportedArray([1, 2, 3, 4, 5, 6]),
    };

    msrCrypto.subtle.generateKey({ name: "Hmac", hash: { name: "Sha-256" }, length: 256 }, true, ["sign","verify"]).then(

        function (e) {

            var aesKey = e;

            msrCrypto.subtle.deriveKey(algorithm, aesKey, { name: "Aes-cbc", length: 1024 }, true, []).then(
                function (e) {
                    shared.getKeyData(e, function (keyData) {
                         start();
                         equal(shared.base64UrlToBytes(keyData.k).length, 1024, "Key length correct.");
                    });
                },
                kdfError("deriveKey error")
            );
         },
        kdfError("generateKey error")
    );
});

asyncTest("Aes 256 -> Aes 1024", function () {

    var algorithm = {
        name: "Concat",
        hash: { name: "Sha-256" },
        algorithmId: [1, 2, 3, 4, 5, 6],
        partyUInfo: [1, 2, 3, 4, 5, 6],
        partyVInfo: [1, 2, 3, 4, 5, 6]
    };

    msrCrypto.subtle.generateKey({ name: "Aes-cbc", length: 256 }, true, ["deriveKey"]).then(

        function (e) {
            var aesKey = e;
            msrCrypto.subtle.deriveKey(algorithm, aesKey, { name: "Aes-cbc", length: 1024 }, true, []).then(

                function (e) {
                    shared.getKeyData(e, function (keyData) {
                        start();
                        equal(shared.base64UrlToBytes(keyData.k).length, 1024, "Key length correct.");
                    });
                },
                kdfError("deriveKey error")
                );
        },
        kdfError("generateKey error")
    );

});

function kdfError(message) {
    return function (e) {
        start();
        ok(false, message + " " + e.message);
    };
}

