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


// This script contains a dotNet crypto interface to call from JavaScript

var dotNet = (function () {

    var webServerice = "../dotNetWebService/DotNetWebService.asmx";

    function dotNetCrypto(functionName, parameters) {
        var xmlhttp;
        if (window.XMLHttpRequest) {
            xmlhttp = new XMLHttpRequest();
        } else if (window.ActiveXObject) {
            xmlhttp = new window.ActiveXObject("Msxml2.XMLHTTP");
        }

        xmlhttp.open("POST", webServerice + "/" + functionName, false);
        xmlhttp.setRequestHeader("content-type", "application/json");
        xmlhttp.setRequestHeader("Accept", "application/json");
        xmlhttp.send(parameters);
        if (xmlhttp.status === 200) {
            var jsonResultBuffer = xmlhttp.responseText;
            var result = JSON.parse(jsonResultBuffer);
            // The web method magicaly creates a property 'd' for the result
            return result.d;
        }
        if (xmlhttp.status === 404) {
            throw new Error(xmlhttp.responseText);
        }
        if (xmlhttp.status === 500) {
            throw new Error(xmlhttp.responseText);
        }

    }

    return {

        getRandomBytes: function (array) {

            var parameters = {
                numberOfBytes: array.length
            };

            var result = dotNetCrypto("getRandomBytes", JSON.stringify(parameters));

            for (var i = 0; i < result.length; i++) {
                array[i] = result[i];
            }

            return;
        },

        encrypt: function (publicKey, plainBytes, hashAlgorithm) {

            var parameters = {
                publicKey: JSON.parse(publicKey),
                plainBytes: plainBytes,
                hashAlgorithm: hashAlgorithm
            };

            // When we get the rsa key from the .net service, it has a __type
            // field added to it by the automatic serialization process. We need
            // to remove it or we'll get an error when we send the key back because
            // it will be an unexpected field.
            delete parameters.publicKey.__type;

            var result = dotNetCrypto("encrypt", JSON.stringify(parameters));

            return result;
        },

        decrypt: function (privateKey, cipherBytes, hashAlgorithm) {

            var parameters = {
                privateKey: JSON.parse(privateKey),
                cipherBytes: cipherBytes,
                hashAlgorithm: hashAlgorithm
            };

            // When we get the rsa key from the .net service, it has a __type
            // field added to it by the automatic serialization process. We need
            // to remove it or we'll get an error when we send the key back because
            // it will be an unexpected field.
            delete parameters.privateKey.__type;

            var result = dotNetCrypto("decrypt", JSON.stringify(parameters));

            if (result.error) {
                throw new Error(result.error);
            }

            return result;
        },

        sign: function (mode, privateKey, plainBytes, hashAlgorithm, curveName) {

            var parameters = {
                mode : mode,
                privateKey: JSON.parse(privateKey),
                plainBytes: plainBytes,
                hashAlgorithm: hashAlgorithm,
                curveName: curveName || null
            };

            // When we get the rsa key from the .net service, it has a __type
            // field added to it by the automatic serialization process. We need
            // to remove it or we'll get an error when we send the key back because
            // it will be an unexpected field.
            delete parameters.privateKey.__type;

            var result = dotNetCrypto("sign", JSON.stringify(parameters));

            return result;
        },

        verify: function (mode, publicKey, plainBytes, signatureBytes, hashAlgorithm, curveName) {

            var parameters = {
                mode: mode,
                publicKey: JSON.parse(publicKey),
                plainBytes: plainBytes,
                hashAlgorithm: hashAlgorithm,
                signatureBytes: signatureBytes,
                curveName : curveName || null
            };

            // When we get the rsa key from the .net service, it has a __type
            // field added to it by the automatic serialization process. We need
            // to remove it or we'll get an error when we send the key back because
            // it will be an unexpected field.
            delete parameters.publicKey.__type;

            var result = dotNetCrypto("verify", JSON.stringify(parameters));

            if (result.error) {
                throw new Error(result.error);
            }

            return result;
        },

        deriveBits: function (publicKey, hashAlgorithmName) {

            var parameters = {
                publicKey: publicKey,
                hashAlgorithmName: hashAlgorithmName
            };

            var result = dotNetCrypto("deriveBits", JSON.stringify(parameters));

            if (result.error) {
                throw new Error(result.error);
            }

            return result;
        },

        getRsaKeyPair: function (keySize) {

            var parameters = {
                keySize: keySize
            };

            return dotNetCrypto("getRsaKeyPair", JSON.stringify(parameters));

        },

        getEcKeyPair: function (curveName) {

            var parameters = {
                curveName: curveName
            };

            return dotNetCrypto("getEcKeyPair", JSON.stringify(parameters));

        },

        startProcess: function (testId, testName, machineName, path, userName, password) {

            var parameters = {
                testId: testId,
                testName: testName,
                machineName: machineName,
                path: path,
                userName: userName,
                password: password
            };

            return dotNetCrypto("startProcess", JSON.stringify(parameters));

        },

        postResults: function (id, results, failures) {

            var parameters = {
                id: id,
                results: results,
                failures: failures
            };

            return dotNetCrypto("postResults", JSON.stringify(parameters));

        },

        queryResults: function (id) {

            var parameters = {
                id: id
            };

            return dotNetCrypto("queryResults", JSON.stringify(parameters));

        }

    };

})();