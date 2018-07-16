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
/// <reference path="../dotNet/dotNetInterop.js" />

var subtle;

function addEvent(elem, type, fn) {
    if (elem.addEventListener) {

        // Standards-based browsers
        elem.addEventListener(type, fn, false);
    } else if (elem.attachEvent) {

        // support: IE <9
        elem.attachEvent("on" + type, fn);
    } else {

        // Caller must ensure support for event listeners is present
        throw new Error("addEvent() was called in a context without event listener support");
    }
}

if (document) {
    addEvent(window, "load", function () { subtle = msrCrypto ? msrCrypto.subtle : null; });
}

var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


var shared = {

    runSlowTests: false,

    initPrng: function () {

        var entropy = [];
        for (var i = 0; i < 48; i += 1) {
            entropy[i] = Math.floor(Math.random() * 256);
        }

        // init the prng with the entropy
        msrCrypto.initPrng(entropy);

    },

    typedArraySupport: (typeof Uint8Array !== "undefined"),

    isTypedArray: function (array) {
        return (Object.prototype.toString.call(array) === "[object Uint8Array]");
    },

    textToBytes: function (text) {

        var result = this.newArray(text.length);

        for (var i = 0; i < text.length; i++) {
            result[i] = text.charCodeAt(i);
        }

        return result;
    },

    getArrayResult: function (value) {

        if (Object.prototype.toString.call(value).slice(8, -1) === "ArrayBuffer") {
            var uint8 = new Uint8Array(value);
            return (uint8.length === 1) ? [uint8[0]] : Array.apply(null, uint8);
        }

        return value;

    },

    bytesToHexString: function (bytes) {
        var result = "";

        for (var i = 0 ; i < bytes.length; i++) {

            if (i % 4 == 0 && i != 0) result += "-";

            var hexval = bytes[i].toString(16).toUpperCase();
            // add a leading zero if needed
            if (hexval.length == 1)
                result += "0";

            result += hexval;
        }

        return result;
    },

    keyTextToKeyData: function (keyType, keyText) {

        switch (keyType) {
            case "aes":
                return { kty: "oct", k: keyText, ext: true };

            case "hmac":
                return { kty: "oct", alg: "HS256", k: keyText, ext: true };

            case "rsa":
                return shared.textToBytes(keyText);

            default:
                throw new Error("invalid key type");
        }

    },

    hexToBytesArray: function (hexString) {

        hexString = hexString.replace(/[^A-Fa-f0-9]/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return shared.toSupportedArray(result);
    },

    toSupportedArray: function (dataArray) {

        //already typed array and hence supported
        if (shared.isTypedArray(dataArray)) {
            return dataArray;
        }

        //convert to typed array
        if (shared.typedArraySupport) {
            return new Uint8Array(dataArray);
        }

        //typed arrays not supported
        return dataArray;

    },

    newArray: function (size) {

        if (shared.typedArraySupport) {
            return new Uint8Array(size);
        }
        return new Array(size);
    },

    slice: function (array, start, end) {

        if (shared.typedArraySupport) {
            return array.subarray(start, end);
        }
        return array.slice(start, end);
    },

    partitionData: function (dataArray) {

        var result = [];
        var i = 0;

        while (i < dataArray.length) {
            var randomnumber = Math.floor(Math.random() * dataArray.length + 1) + i;
            result.push(shared.slice(dataArray, i, randomnumber));
            i = randomnumber;
        }

        return result;
    },

    importKey: function (keyType, keyData, callback, errorCallback, callbackParams) {

        var keyOp = null;

        if (keyType == 'hmac') {
            keyOp = subtle.importKey("jwk", keyData, { name: "Hmac", hash: { name: "Sha-256" } }, true, ["sign"]);

        } else if (keyType == 'aes-cbc') {
            keyOp = subtle.importKey("jwk", keyData, { name: "Aes-cbc" }, true, ["encrypt", "decrypt"]);

        } else if (keyType == 'aes-gcm') {
            keyOp = subtle.importKey("jwk", keyData, { name: "Aes-gcm" }, true, ["encrypt", "decrypt"]);

        } else {
            throw new Error("invalid keyType");
        }

        keyOp.then(
            function (result) {
                callback(result, callbackParams);
            },
            function (e) {
                errorCallback(e);
            }
        );

        return;
    },

    importKeyBytes: function (keyType, keyBytes, callback, errorCallback, callbackParams) {

        //convert from bytes ==> string ==> straight Base64 ==> Base64Url
        var keyText = shared.toBase64(keyBytes, true);

        var keyData = shared.keyTextToKeyData("hmac", keyText);

        shared.importKey(keyType, keyData, callback, errorCallback, callbackParams);

        return;
    },

    flip: function (percent) {

        if (percent > 1) {
            percent = (percent / 100);
        }
        return (Math.random() > percent);
    },

    hexStringToBase64Url: function (hexString) {
        var bytes = shared.hexToBytes(hexString);
        var b64Url = shared.toBase64(bytes);
        return b64Url.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
    },

    error: function (message) {
        return function (e) {
            start();
            ok(false, message + " " + e.message);
        }
    },

    setAsyncState: function (state) {

        if (state) {
            msrCrypto.subtle.forceSync = true;
        }

        if (Math.random() >= 0.5) {
            msrCrypto.subtle.forceSync = false;
        } else {
            (msrCrypto.subtle.forceSync !== undefined) && delete msrCrypto.subtle.forceSync;
        }

    },

    base64UrlToBytes: function (base64UrlText) {

        return shared.base64ToBytes(base64UrlText);
    },

    getKeyData: function (keyHandle, callback, callbackParam) {

        subtle.exportKey("jwk", keyHandle, true, []).then(
            function (result) {


                callback(result, callbackParam);
            }
        );
    },

    hexToBytes: function (hexString) {

        hexString = hexString.replace(/\-/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return result;
    },

    toBase64: function toBase64(data, base64Url) {
        /// <signature>
        ///     <summary>Converts byte data to Base64 string</summary>
        ///     <param name="data" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="base64Url" type="Boolean" optional="true">Converts to a Base64Url string if True (default = false)</param>
        ///     <returns type="String" />
        /// </signature>
        /// <signature>
        ///     <summary>Converts byte data to Base64 string</summary>
        ///     <param name="data" type="UInt8Array">A UInt8Array</param>
        ///     <param name="base64Url" type="Boolean" optional="true">Converts to a Base64Url string if True (default = false)</param>
        ///     <returns type="String" />
        /// </signature>
        /// <signature>
        ///     <summary>Converts text to Base64 string</summary>
        ///     <param name="data" type="String">Text string</param>
        ///     <param name="base64Url" type="Boolean" optional="true">Converts to a Base64Url string if True (default = false)</param>
        ///     <returns type="String" />
        /// </signature>

        var output = "";

        if (!base64Url) {
            base64Url = false;
        }

        // If the input is an array type, convert it to a string.
        // The built-in btoa takes strings.
        if (data.pop || data.subarray) {
            data = String.fromCharCode.apply(null, data);
        }

        if (typeof btoa != 'undefined') {
            output = btoa(data);
        } else {

            var char1, char2, char3, enc1, enc2, enc3, enc4;
            var i;

            for (i = 0; i < data.length; i += 3) {

                // Get the next three chars.
                char1 = data.charCodeAt(i);
                char2 = data.charCodeAt(i + 1);
                char3 = data.charCodeAt(i + 2);

                // Encode three bytes over four 6-bit values.
                // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].
                // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].

                // 'enc1' = high 6-bits from char1
                enc1 = char1 >> 2;
                // 'enc2' = 2 low-bits of char1 + 4 high-bits of char2
                enc2 = ((char1 & 0x3) << 4) | (char2 >> 4);
                // 'enc3' = 4 low-bits of char2 + 2 high-bits of char3
                enc3 = ((char2 & 0xF) << 2) | (char3 >> 6);
                // 'enc4' = 6 low-bits of char3
                enc4 = char3 & 0x3F;

                // 'char2' could be 'nothing' if there is only one char left to encode
                //   if so, set enc3 & enc4 to 64 as padding.
                if (isNaN(char2)) {
                    enc3 = enc4 = 64;

                    // If there was only two chars to encode char3 will be 'nothing'
                    //   set enc4 to 64 as padding.
                } else if (isNaN(char3)) {
                    enc4 = 64;
                }

                // Lookup the base-64 value for each encoding.
                output = output +
                encodingChars.charAt(enc1) +
                encodingChars.charAt(enc2) +
                encodingChars.charAt(enc3) +
                encodingChars.charAt(enc4);
            }
        }

        if (base64Url) {
            return output.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        }

        return output;
    },

    base64ToBytes: function base64ToBytes(encodedString) {
        /// <signature>
        ///     <summary>Converts a Base64/Base64Url string to an Array</summary>
        ///     <param name="encodedString" type="String">A Base64/Base64Url encoded string</param>
        ///     <returns type="Array" />
        /// </signature>

        // This could be encoded as base64url (different from base64)
        encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

        // In case the padding is missing, add some.
        while (encodedString.length % 4 !== 0) {
            encodedString += "=";
        }

        var output = [];
        var char1, char2, char3;
        var enc1, enc2, enc3, enc4;
        var i;

        // Remove any chars not in the base-64 space.
        encodedString = encodedString.replace(/[^A-Za-z0-9\+\/\=]/g, "");

        for (i = 0; i < encodedString.length; i += 4) {

            // Get 4 characters from the encoded string.
            enc1 = encodingChars.indexOf(encodedString.charAt(i));
            enc2 = encodingChars.indexOf(encodedString.charAt(i + 1));
            enc3 = encodingChars.indexOf(encodedString.charAt(i + 2));
            enc4 = encodingChars.indexOf(encodedString.charAt(i + 3));

            // Convert four 6-bit values to three characters.
            // [A7,A6,A5,A4,A3,A2][A1,A0,B7,B6,B5,B4][B3,B2,B1,B0,C7,C6][C5,C4,C3,C2,C1,C0].
            // [A7,A6,A5,A4,A3,A2,A1,A0][B7,B6,B5,B4,B3,B2,B1,B0][C7,C6,C5,C4,C3,C2,C1,C0].

            // 'char1' = all 6 bits of enc1 + 2 high-bits of enc2.
            char1 = (enc1 << 2) | (enc2 >> 4);
            // 'char2' = 4 low-bits of enc2 + 4 high-bits of enc3.
            char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
            // 'char3' = 2 low-bits of enc3 + all 6 bits of enc4.
            char3 = ((enc3 & 3) << 6) | enc4;

            // Convert char1 to string character and append to output
            output.push(char1);

            // 'enc3' could be padding
            //   if so, 'char2' is ignored.
            if (enc3 !== 64) {
                output.push(char2);
            }

            // 'enc4' could be padding
            //   if so, 'char3' is ignored.
            if (enc4 !== 64) {
                output.push(char3);
            }

        }

        return output;

    },

    getRsaKeyPair: function (rsaAlg, callback) {

        var nativeCrytpoApi = window.crypto || window.msCrypto;

        var keyOp1 = nativeCrytpoApi.subtle.generateKey(
            rsaAlg,
            true, []);

        keyOp1.oncomplete = function (e) {

            var ie11 = (e.target);

            var publicKey = ie11 ? e.target.result.publicKey : e.publicKey;
            var privateKey = ie11 ? e.target.result.privateKey : e.privateKey;

            var keyHandlePrivate,
                keyHandlePublic,
                keyHandlePrivateIE,
                keyHandlePublicIE

            var keyExpOp1 = nativeCrytpoApi.subtle.exportKey("jwk", privateKey);

            keyExpOp1.oncomplete = function (e0) {

                if (ie11) {
                    var keyBytes = shared.getArrayResult(e0.target.result);
                    var keyString = String.fromCharCode.apply(null, keyBytes);
                    e0 = JSON.parse(keyString);
                }

                subtle.importKey("jwk", e0, rsaAlg, true, []).then(

                    function (keyHandlePrivate) {

                        var keyExpOp2 = nativeCrytpoApi.subtle.exportKey("jwk", publicKey);

                        keyExpOp2.oncomplete = function (e3) {

                            if (ie11) {
                                var keyBytes = shared.getArrayResult(e3.target.result);
                                var keyString = String.fromCharCode.apply(null, keyBytes);
                                e3 = JSON.parse(keyString);
                            }

                            subtle.importKey("jwk", e3, rsaAlg, true, []).then(

                                function (keyHandlePublic) {

                                    var keyData = {
                                        keyHandlePublic: keyHandlePublic,
                                        keyHandlePrivate: keyHandlePrivate,
                                        keyHandlePrivateIE: privateKey,
                                        keyHandlePublicIE: publicKey
                                    };

                                    callback(keyData);
                                }
                            );
                        };
                    }
                );
            }
        }
    }
}