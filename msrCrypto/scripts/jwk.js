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

/* global msrcryptoUtilities */

/// <reference path="utilities.js" />

/// <dictionary>alg,Jwk,msrcrypto,utils</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoJwk = (function () {

    var utils = msrcryptoUtilities;

    function stringToArray(stringData) {

        var result = [];

        for (var i = 0; i < stringData.length; i++) {
            result[i] = stringData.charCodeAt(i);
        }

        if (result[result.length - 1] === 0) {
            result.pop();
        }

        return result;
    }

    function getKeyType(keyHandle) {

        var algType = keyHandle.algorithm.name.slice(0, 3).toLowerCase();

        if (algType === "rsa") {
            return "RSA";
        }

        if (algType === "ecd") {
            return "EC";
        }

        return "oct";
    }

    var algorithmMap = {
    
        hmac : function(algorithm) {
                    return "HS" + algorithm.hash.name.substring(algorithm.hash.name.indexOf('-') + 1);
        },

        "aes-cbc" : function(algorithm) {
            return "A" + algorithm.length.toString() + "CBC";
        },

        "aes-gcm" : function(algorithm) {
            return "A" + algorithm.length.toString() + "GCM";
        },

        "rsaes-pkcs1-v1_5": function (algorithm) {

            return "RSA1_5";
        },

        "rsassa-pkcs1-v1_5": function (algorithm) {

           return "RS" + algorithm.hash.name.substring(algorithm.hash.name.indexOf('-') + 1);

        },

        "rsa-oaep": function (algorithm) {

            return "RS-OAEP-" + algorithm.hash.name.substring(algorithm.hash.name.indexOf('-') + 1);
        },

        "rsa-pss": function (algorithm) {

            return "PS" + algorithm.hash.name.substring(algorithm.hash.name.indexOf('-') + 1);
        },

        "ecdsa": function (algorithm) {

            return "EC-" + algorithm.namedCurve.substring(algorithm.namedCurve.indexOf('-') + 1);
        }
    };

    function keyToJwk(keyHandle, keyData) {

        var key = {};

        key.kty = getKeyType(keyHandle);
        key.ext = keyHandle.extractable;
        key.alg = algorithmMap[keyHandle.algorithm.name.toLowerCase()](keyHandle.algorithm);
        key.key_ops = keyHandle.keyUsage;

        // Using .pop to determine if a property value is an array.
        if (keyData.pop) {
            key.k = utils.toBase64(keyData, true);
        } else {
            // Convert the base64Url properties to byte arrays
            for (var property in keyData) {
                if (keyData[property].pop) {
                    key[property] = utils.toBase64(keyData[property], true);
                }
            }
        }

        if (keyHandle.algorithm.namedCurve) {
            key["crv"] = keyHandle.algorithm.namedCurve;
        }

        return key;

    }

    function keyToJwkOld(keyHandle, keyData) {

        var key = {};

        key.kty = getKeyType(keyHandle);
        key.extractable = keyHandle.extractable;

        // Using .pop to determine if a property value is an array.
        if (keyData.pop) {
            key.k = utils.toBase64(keyData, true);
        } else {
            // Convert the base64Url properties to byte arrays
            for (var property in keyData) {
                if (keyData[property].pop) {
                    key[property] = utils.toBase64(keyData[property], true);
                }
            }
        }

        if (keyHandle.algorithm.namedCurve) {
            key["crv"] = keyHandle.algorithm.namedCurve;
        }

        var stringData = JSON.stringify(key, null, '\t');

        return stringToArray(stringData);

    }

    // 'jwkKeyData' is an array of bytes. Each byte is a charCode for a json key string
    function jwkToKey(keyData, algorithm, propsToArray) {


        // Convert the json string to an object
        var jsonKeyObject = JSON.parse(JSON.stringify(keyData)); //JSON.parse(jsonString);

        // Convert the base64url encoded properties to byte arrays
        for (var i = 0; i < propsToArray.length; i += 1) {
            var propValue = jsonKeyObject[propsToArray[i]];
            if (propValue) {
                jsonKeyObject[propsToArray[i]] = 
                   utils.base64ToBytes(propValue);
            }
        }

        return jsonKeyObject;
    }

    return {
        keyToJwkOld: keyToJwkOld,
        keyToJwk: keyToJwk,
        jwkToKey: jwkToKey
    };
})();