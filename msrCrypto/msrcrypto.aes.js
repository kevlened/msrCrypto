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

/* jshint -W016 */ /* repress binary operator errors */
/* jshint -W052 */ /* repress complaint about binary NOT operator*/
var msrCryptoVersion = "1.5.6";
var msrCrypto = msrCrypto || (function () {


    "use strict";
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

var operations = {};

operations.register = function (operationType, algorithmName, functionToCall) {

    if (!operations[operationType]) {
        operations[operationType] = {};
    }

    var op = operations[operationType];

    if (!op[algorithmName]) {
        op[algorithmName] = functionToCall;
    }

};

operations.exists = function (operationType, algorithmName) {
    if (!operations[operationType]) {
        return false;
    }

    return (operations[operationType][algorithmName]) ? true : false;
};
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

/* global self */
/* jshint -W098 */
/* W098 is 'defined but not used'. These properties are used in other scripts. */

/// <reference path="jsCopDefs.js" />

// Sets the url to for this script.
// We need this to pass to webWorkers later to instantiate them.

/// <dictionary>fprng</dictionary>

/// #endregion JSCop/JsHint

/// Store the URL for this script. We will need this later to instantiate
/// new web workers (if supported).
var scriptUrl = (function () {

    /* jshint -W117 */

    if (typeof document !== "undefined") {
        // Use error.stack to find out the name of this script
        try {
            throw new Error();
        } catch (e) {
            if (e.stack) {
                var match = /\w+:\/\/(.+?\/)*.+\.js/.exec(e.stack);
                return (match && match.length > 0) ? match[0] : null;
            }
        }
    } else if (typeof self !== "undefined") {
        // If this script is being run in a WebWorker, 'document' will not exist
        //  but we can use self.        
        return self.location.href;
    }

    // We must be running in an environment without document or self.
    return null;

    /* jshint +W117 */

})();

// Indication if the user provided entropy into the entropy pool.
var fprngEntropyProvided = false;

// Support for webWorkers IE10+.
var webWorkerSupport = (typeof Worker !== "undefined");

// Is this script running in an instance of a webWorker?
var runningInWorkerInstance = (typeof importScripts !== "undefined");

// Typed Arrays support?
var typedArraySupport = (typeof Uint8Array !== "undefined");

// Property setter/getter support IE9+.
var setterSupport = (function () {
    try {
        Object.defineProperty({}, "oncomplete", {});
        return true;
    } catch (ex) {
        return false;
    }
}());

// Run in async mode (requires web workers) and user can override to sync mode
//  by setting the .forceSync property to true on the subtle interface
//  this can be changes 'on the fly'.
var asyncMode = webWorkerSupport;

var createProperty = function (parentObject, propertyName, /*@dynamic*/initialValue, getterFunction, setterFunction) {
    /// <param name="parentObject" type="Object"/>
    /// <param name="propertyName" type="String"/>
    /// <param name="initialValue" type="Object"/>
    /// <param name="getterFunction" type="Function"/>
    /// <param name="setterFunction" type="Function" optional="true"/>

    if (!setterSupport) {
        parentObject[propertyName] = initialValue;
        return;
    }

    var setGet = {};

    getterFunction && (setGet.get = getterFunction);
    setterFunction && (setGet.set = setterFunction);

    Object.defineProperty(
        parentObject,
        propertyName, setGet);
};

// Collection of hash functions for global availability.
// Each hashfunction will add itself to the collection as it is evaluated.
var msrcryptoHashFunctions = {};
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

/* jshint -W016 */

/// <reference path="global.js" />
/// <reference path="jsCopDefs.js" />

/// <dictionary>
///    msrcrypto, Btoa, uint, hexval, res, xor
/// </dictionary>

/// #endregion JSCop/JsHint

var msrcryptoUtilities = (function () {

    var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    var btoaSupport = (typeof btoa !== "undefined");

    function toBase64(data, base64Url) {
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

        if (btoaSupport) {
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
    }

    function base64ToString(encodedString) {
        /// <signature>
        ///     <summary>Converts a Base64/Base64Url string to a text</summary>
        ///     <param name="encodedString" type="String">A Base64/Base64Url encoded string</param>
        ///     <returns type="String" />
        /// </signature>

        if (btoaSupport) {

            // This could be encoded as base64url (different from base64)
            encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

            // In case the padding is missing, add some.
            while (encodedString.length % 4 !== 0) {
                encodedString += "=";
            }

            return atob(encodedString);
        }

        return String.fromCharCode.apply(null, base64ToBytes(encodedString));

    }

    function base64ToBytes(encodedString) {
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

    }

    function getObjectType(object) {
        /// <signature>
        ///     <summary>Returns the name of an object type</summary>
        ///     <param name="object" type="Object"></param>
        ///     <returns type="String" />
        /// </signature>

        return Object.prototype.toString.call(object).slice(8, -1);
    }

    function bytesToHexString(bytes, separate) {
        /// <signature>
        ///     <summary>Converts an Array of bytes values (0-255) to a Hex string</summary>
        ///     <param name="bytes" type="Array"/>
        ///     <param name="separate" type="Boolean" optional="true">Inserts a separator for display purposes (default = false)</param>
        ///     <returns type="String" />
        /// </signature>

        var result = "";
        if (typeof separate === "undefined") {
            separate = false;
        }

        for (var i = 0; i < bytes.length; i++) {

            if (separate && (i % 4 === 0) && i !== 0) {
                result += "-";
            }

            var hexval = bytes[i].toString(16).toUpperCase();
            // Add a leading zero if needed.
            if (hexval.length === 1) {
                result += "0";
            }

            result += hexval;
        }

        return result;
    }

    function bytesToInt32(bytes, index) {
        /// <summary>
        /// Converts four bytes to a 32-bit int
        /// </summary>
        /// <param name="bytes">The bytes to convert</param>
        /// <param name="index" optional="true">Optional starting point</param>
        /// <returns type="Number">32-bit number</returns>
        index = (index || 0);

        return (bytes[index] << 24) |
               (bytes[index + 1] << 16) |
               (bytes[index + 2] << 8) |
                bytes[index + 3];
    }

    function stringToBytes(messageString) {
        /// <signature>
        ///     <summary>Converts a String to an Array of byte values (0-255)</summary>
        ///     <param name="messageString" type="String"/>
        ///     <returns type="Array" />
        /// </signature>

        var bytes = new Array(messageString.length);

        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = messageString.charCodeAt(i);
        }

        return bytes;
    }

    function hexToBytesArray(hexString) {
        /// <signature>
        ///     <summary>Converts a Hex-String to an Array of byte values (0-255)</summary>
        ///     <param name="hexString" type="String"/>
        ///     <returns type="Array" />
        /// </signature>

        hexString = hexString.replace(/\-/g, "");

        var result = [];
        while (hexString.length >= 2) {
            result.push(parseInt(hexString.substring(0, 2), 16));
            hexString = hexString.substring(2, hexString.length);
        }

        return result;
    }

    function clone(object) {
        /// <signature>
        ///     <summary>Creates a shallow clone of an Object</summary>
        ///     <param name="object" type="Object"/>
        ///     <returns type="Object" />
        /// </signature>

        var newObject = {};
        for (var propertyName in object) {
            if (object.hasOwnProperty(propertyName)) {
                newObject[propertyName] = object[propertyName];
            }
        }
        return newObject;
    }

    function unpackData(base64String, arraySize, toUint32s) {
        /// <signature>
        ///     <summary>Unpacks Base64 encoded data into arrays of data.</summary>
        ///     <param name="base64String" type="String">Base64 encoded data</param>
        ///     <param name="arraySize" type="Number" optional="true">Break data into sub-arrays of a given length</param>
        ///     <param name="toUint32s" type="Boolean" optional="true">Treat data as 32-bit data instead of byte data</param>
        ///     <returns type="Array" />
        /// </signature>

        var bytes = base64ToBytes(base64String),
            data = [],
            i;

        if (isNaN(arraySize)) {
            return bytes;
        } else {
            for (i = 0; i < bytes.length; i += arraySize) {
                data.push(bytes.slice(i, i + arraySize));
            }
        }

        if (toUint32s) {
            for (i = 0; i < data.length; i++) {
                data[i] = (data[i][0] << 24) + (data[i][1] << 16) + (data[i][2] << 8) + data[i][3];
            }
        }

        return data;
    }

    function int32ToBytes(int32) {
        /// <signature>
        ///     <summary>Converts a 32-bit number to an Array of 4 bytes</summary>
        ///     <param name="int32" type="Number">32-bit number</param>
        ///     <returns type="Array" />
        /// </signature>
        return [(int32 >>> 24) & 255, (int32 >>> 16) & 255, (int32 >>> 8) & 255, int32 & 255];
    }

    function int32ArrayToBytes(int32Array) {
        /// <signature>
        ///     <summary>Converts an Array 32-bit numbers to an Array bytes</summary>
        ///     <param name="int32Array" type="Array">Array of 32-bit numbers</param>
        ///     <returns type="Array" />
        /// </signature>

        var result = [];
        for (var i = 0; i < int32Array.length; i++) {
            result = result.concat(int32ToBytes(int32Array[i]));
        }
        return result;
    }

    function xorVectors(a, b) {
        /// <signature>
        ///     <summary>Exclusive OR (XOR) two arrays.</summary>
        ///     <param name="a" type="Array">Input array.</param>
        ///     <param name="b" type="Array">Input array.</param>
        ///     <returns type="Array">XOR of the two arrays. The length is minimum of the two input array lengths.</returns>
        /// </signature>

        var length = Math.min(a.length, b.length),
            res = new Array(length);
        for (var i = 0 ; i < length ; i += 1) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }

    function getVector(length, fillValue) {
        /// <signature>
        ///     <summary>Get an array filled with zeroes (or optional fillValue.)</summary>
        ///     <param name="length" type="Number">Requested array length.</param>
        ///     <param name="fillValue" type="Number" optional="true"></param>
        ///     <returns type="Array"></returns>
        /// </signature>

        // Use a default value of zero
        fillValue || (fillValue = 0);

        var res = new Array(length);
        for (var i = 0; i < length; i += 1) {
            res[i] = fillValue;
        }
        return res;
    }

    function toArray(typedArray) {
        /// <signature>
        ///     <summary>Converts a UInt8Array to a regular JavaScript Array</summary>
        ///     <param name="typedArray" type="UInt8Array"></param>
        ///     <returns type="Array"></returns>
        /// </signature>

        // If undefined or null return an empty array
        if (!typedArray) {
            return [];
        }

        // If already an Array return it
        if (typedArray.pop) {
            return typedArray;
        }

        // If it's an ArrayBuffer, convert it to a Uint8Array first
        if (typedArray.isView || getObjectType(typedArray) === "ArrayBuffer") {
            typedArray = new Uint8Array(typedArray);
        }

        // A single element array will cause a new Array to be created with the length
        // equal to the value of the single element. Not what we want.
        // We'll return a new single element array with the single value.
        return (typedArray.length === 1) ? [typedArray[0]] : Array.apply(null, typedArray);
    }

    function padEnd(array, value, finalLength) {
        /// <signature>
        ///     <summary>Pads the end of an array with a specified value</summary>
        ///     <param name="array" type="Array"></param>
        ///     <param name="value" type="Number">The value to pad to the array</param>
        ///     <param name="finalLength" type="Number">The final resulting length with padding</param>
        ///     <returns type="Array"></returns>
        /// </signature>

        while (array.length < finalLength) {
            array.push(value);
        }

        return array;
    }

    function padFront(array, value, finalLength) {
        /// <signature>
        ///     <summary>Pads the front of an array with a specified value</summary>
        ///     <param name="array" type="Array"></param>
        ///     <param name="value" type="Number">The value to pad to the array</param>
        ///     <param name="finalLength" type="Number">The final resulting length with padding</param>
        ///     <returns type="Array"></returns>
        /// </signature>

        while (array.length < finalLength) {
            array.unshift(value);
        }

        return array;
    }

    function arraysEqual(array1, array2) {
        /// <signature>
        ///     <summary>Checks if two Arrays are equal by comparing their values.</summary>
        ///     <param name="array1" type="Array"></param>
        ///     <param name="array2" type="Array"></param>
        ///     <returns type="Array"></returns>
        /// </signature>

        var result = true;

        if (array1.length !== array2.length) {
            result = false;
        }

        for (var i = 0; i < array1.length; i++) {
            if (array1[i] !== array2[i]) {
                result = false;
            }
        }

        return result;
    }

    function verifyByteArray(array) {
        /// <signature>
        ///     <summary>Verify that an Array contains only byte values (0-255)</summary>
        ///     <param name="array" type="Array"></param>
        ///     <returns type="Boolean">Returns true if all values are 0-255</returns>
        /// </signature>

        if (getObjectType(array) !== "Array") {
            return false;
        }

        var element;

        for (var i = 0; i < array.length; i++) {

            element = array[i];

            if (isNaN(element) || element < 0 || element > 255) {
                return false;
            }
        }

        return true;
    }

    return {
        toBase64: toBase64,
        base64ToString: base64ToString,
        base64ToBytes: base64ToBytes,
        getObjectType: getObjectType,
        bytesToHexString: bytesToHexString,
        bytesToInt32: bytesToInt32,
        stringToBytes: stringToBytes,
        unpackData: unpackData,
        hexToBytesArray: hexToBytesArray,
        int32ToBytes: int32ToBytes,
        int32ArrayToBytes: int32ArrayToBytes,
        toArray: toArray,
        arraysEqual: arraysEqual,
        clone: clone,
        xorVectors: xorVectors,
        padEnd: padEnd,
        padFront: padFront,
        getVector: getVector,
        verifyByteArray: verifyByteArray
    };

})();
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
/* global fprngEntropyProvided: true */
/* global runningInWorkerInstance */
/* global self */
/* global operations */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="random.js" />

/// <dictionary>
///    msrcrypto, webworker, func, onmessage, prng
/// </dictionary>

/// #endregion JSCop/JsHint

var msrcryptoWorker = (function () {

    // If we're running in a webworker we need to postMessage to return our result
    //   otherwise just return the value as normal.
    function returnResult(result) {
        if (runningInWorkerInstance) {
            self.postMessage(result);
        }
        return result;
    }

    return {

        jsCryptoRunner: function (/*@type(typeEvent)*/ e) {

            var operation = e.data.operationType;
            var result;

            if (!operations.exists(operation, e.data.algorithm.name)) {
                throw new Error("unregistered algorithm.");
            }

            var func = operations[operation][e.data.algorithm.name];

            var /*@dynamic*/ p = e.data;

            if (p.operationSubType === "process") {
                func(p);
                result = returnResult({ type: "process" });
            } else {
                result = returnResult(func(p));
            }

            return result;
        }
    };

})();

// If this is running in a webworker we need self.onmessage to receive messages from
//   the calling script.
// If we are in 'synchronous mode' (everything running in one script)
//   we don't want to override self.onmessage.
if (runningInWorkerInstance) {

    self.onmessage = function (/*@type(typeEvent)*/e) {

        // When this worker first gets instantiated we will receive seed data
        //   for this workers prng.
        if (e.data.prngSeed) {
            var entropy = e.data.prngSeed;
            msrcryptoPseudoRandom.init(entropy);
            return;
        }

        // Process the crypto operation
        msrcryptoWorker.jsCryptoRunner(e);
    };
}
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
/// #region JSCop/JsHint

/// <disable>
/// JS2025.InsertSpaceBeforeCommentText,
/// JS2027.PunctuateCommentsCorrectly,
/// JS2074.IdentifierNameIsMisspelled,
/// JS3056.DeclareVariablesOnceOnly,
/// JS3053.IncorrectNumberOfArguments,
/// JS2005.UseShortFormInitializations,
/// JS2073.CommentIsMisspelled,
/// JS3092.DeclarePropertiesBeforeUse
/// </disable>

/// #endregion JSCop/JsHint

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

function BlockFunctionTypeDef(message, blockIndex, initialHashValues, k, w) {
    /// <signature>
    ///     <summary>
    ///         Type definition for block function
    ///     </summary>
    ///     <param name="message" type="Array">Block data</param>
    ///     <param name="blockIndex" type="Number">Block number to operate on</param>
    ///     <param name="initialHashValues" type="Array"></param>
    ///     <param name="k" type="Array">K constants</param>
    ///     <param name="w" type="Array">Array to hold w values</param>
    ///     <returns type="Array">Hash values</returns>
    /// </signature>

    return [];
}

var msrcryptoSha = function (name, der, h, k, blockBytes, blockFunction, truncateTo) {
    /// <summary>
    /// Returns a hash function using the passed in parameters.
    /// </summary>
    /// <param name="name" type="String">Name of the hash function.</param>
    /// <param name="der" type="Array"></param>
    /// <param name="h" type="Array"></param>
    /// <param name="k" type="Array"></param>
    /// <param name="blockBytes" type="Number">The number of bytes in a block.</param>
    /// <param name="blockFunction" type="BlockFunctionTypeDef">Function for processing blocks.</param>
    /// <param name="truncateTo" type="Number">Truncate the resulting hash to a fixed length.</param>
    /// <returns type="Object"></returns>

    var utils = msrcryptoUtilities;

    // Make a copy of h so we don't alter the initialization array.
    var hv = h.slice(),
        w = new Array(blockBytes),
        buffer = [],
        blocksProcessed = 0;

    function hashBlocks(message) {
        /// <summary>
        /// Breaks a array of data into full blocks and hashes each block in sequence.
        /// Data at the end of the message that does not fill an entire block is
        /// returned.
        /// </summary>
        /// <param name="message" type="Array">Byte data to hash</param>
        /// <returns type="Array">Unprocessed data at the end of the message that did
        /// not fill an entire block.</returns>

        var blockCount = Math.floor(message.length / blockBytes);

        // Process each  block of the message
        for (var block = 0; block < blockCount; block++) {
            blockFunction(message, block, hv, k, w);
        }

        // Keep track of the number of blocks processed.
        // We have to put the total message size into the padding.
        blocksProcessed += blockCount;

        // Return the unprocessed data.
        return message.slice(blockCount * blockBytes);
    }

    function hashToBytes() {
        /// <summary>
        /// Converts stored hash values (32-bit ints) to bytes.
        /// </summary>
        /// <returns type="Array"></returns>

        // Move the results to an uint8 array.
        var hash = [];

        for (var i = 0; i < hv.length; i++) {
            hash = hash.concat(utils.int32ToBytes(hv[i]));
        }

        // Truncate the results depending on the hash algorithm used.
        hash.length = (truncateTo / 8);

        return hash;
    }

    function addPadding(messageBytes) {
        /// <summary>
        /// Builds and appends padding to a message
        /// </summary>
        /// <param name="messageBytes" type="Array">Message to pad</param>
        /// <returns type="Array">The message array + padding</returns>

        var padLen = blockBytes - messageBytes.length % blockBytes;

        // If there is 8 (16 for sha-512) or less bytes of padding, pad an additional block.
        (padLen <= (blockBytes / 8)) && (padLen += blockBytes);

        // Create a new Array that will contain the message + padding
        var padding = utils.getVector(padLen);

        // Set the 1 bit at the end of the message data
        padding[0] = 128;

        // Set the length equal to the previous data len + the new data len
        var messageLenBits = (messageBytes.length + blocksProcessed * blockBytes) * 8;

        // Set the message length in the last 4 bytes
        padding[padLen - 4] = messageLenBits >>> 24 & 255;
        padding[padLen - 3] = messageLenBits >>> 16 & 255;
        padding[padLen - 2] = messageLenBits >>> 8 & 255;
        padding[padLen - 1] = messageLenBits & 255;

        return messageBytes.concat(padding);
    }

    function computeHash(messageBytes) {
        /// <summary>
        /// Computes the hash of an entire message.
        /// </summary>
        /// <param name="messageBytes" type="Array">Byte array to hash</param>
        /// <returns type="Array">Hash of message bytes</returns>

        buffer = hashBlocks(messageBytes);

        return finish();
    }

    function process(messageBytes) {
        /// <summary>
        /// Call process repeatedly to hash a stream of bytes. Then call 'finish' to
        /// complete the hash and get the final result.
        /// </summary>
        /// <param name="messageBytes" type="Array"></param>

        // Append the new data to the buffer (previous unprocessed data)
        buffer = buffer.concat(messageBytes);

        // If there is at least one block of data, hash it
        if (buffer.length >= blockBytes) {

            // The remaining unprocessed data goes back into the buffer
            buffer = hashBlocks(buffer);
        }

        return;
    }

    function finish() {
        /// <summary>
        /// Called after one or more calls to process. This will finalize the hashing
        /// of the 'streamed' data and return the hash.
        /// </summary>
        /// <returns type="Array">Hash of message bytes</returns>

        // All the full blocks of data have been processed. Now we pad the rest and hash.
        // Buffer should be empty now.
        if (hashBlocks(addPadding(buffer)).length !== 0) {
            throw new Error("buffer.length !== 0");
        }

        // Convert the intermediate hash values to bytes
        var result = hashToBytes();

        // Reset the buffer
        buffer = [];

        // Restore the initial hash values
        hv = h.slice();

        // Reset the block counter
        blocksProcessed = 0;

        return result;
    }

    return {
        name: name,
        computeHash: computeHash,
        process: process,
        finish: finish,
        der: der,
        hashLen: truncateTo,
        maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
    };

};

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
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />

/// <dictionary>msrcrypto, der, sha</dictionary>

/// <disable>JS3057.AvoidImplicitTypeCoercion</disable>

/// #endregion JSCop/JsHint

var msrcryptoSha256 = (function () {

    var utils = msrcryptoUtilities;

    function hashBlock(message, blockIndex, hv, k, w) {
        /// <summary>
        /// Block function for hashing algorithm to use.
        /// </summary>
        /// <param name="message" type="Array">Block data to hash</param>
        /// <param name="blockIndex" type="Number">The block of the data to hash</param>
        /// <param name="hv" type="Array">Initial hash values</param>
        /// <param name="k" type="Array">K constants</param>
        /// <param name="w" type="Array">Buffer for w values</param>
        /// <returns type="Array">Updated initial hash values</returns>

        var t, i, temp, x0, x1, blockSize = 64, mask = 0xFFFFFFFF;

        var ra = hv[0],
            rb = hv[1],
            rc = hv[2],
            rd = hv[3],
            re = hv[4],
            rf = hv[5],
            rg = hv[6],
            rh = hv[7];

        // 0 ≤ t ≤ 15
        for (i = 0; i < 16; i++) {
            w[i] = utils.bytesToInt32(message, blockIndex * blockSize + i * 4);
        }

        // 16 ≤ t ≤ 63
        for (t = 16; t < 64; t++) {

            x0 = w[t - 15];
            x1 = w[t - 2];

            w[t] = (((x1 >>> 17) | (x1 << 15)) ^ ((x1 >>> 19) | (x1 << 13)) ^ (x1 >>> 10))
                    + w[t - 7]
                    + (((x0 >>> 7) | (x0 << 25)) ^ ((x0 >>> 18) | (x0 << 14)) ^ (x0 >>> 3))
                    + w[t - 16];

            w[t] = w[t] & mask;
        }

        for (i = 0; i < 64; i++) {

            temp = rh +
                    ((re >>> 6 | re << 26) ^ (re >>> 11 | re << 21) ^ (re >>> 25 | re << 7)) +
                    ((re & rf) ^ ((~re) & rg)) +
                    k[i] + w[i];

            rd += temp;

            temp += ((ra >>> 2 | ra << 30) ^ (ra >>> 13 | ra << 19) ^ (ra >>> 22 | ra << 10)) +
                    ((ra & (rb ^ rc)) ^ (rb & rc));

            rh = rg; // 'h' = g
            rg = rf; // 'g' = f
            rf = re; // 'f' = e
            re = rd; // 'e' = d
            rd = rc; // 'd' = c
            rc = rb; // 'c' = b
            rb = ra; // 'b' = a
            ra = temp; // 'a' = temp

        }

        // Update the hash values
        hv[0] += ra & mask;
        hv[1] += rb & mask;
        hv[2] += rc & mask;
        hv[3] += rd & mask;
        hv[4] += re & mask;
        hv[5] += rf & mask;
        hv[6] += rg & mask;
        hv[7] += rh & mask;

        return hv;
    }

    var k256, h224, h256, der224, der256, upd = utils.unpackData;

    h224 = upd("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q", 4, 1);

    h256 = upd("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk", 4, 1);

    k256 = upd("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g", 4, 1);

    // SHA-224 DER encoding
    // 0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C
    der224 = upd("MC0wDQYJYIZIAWUDBAIEBQAEHA");

    // SHA-256 DER encoding
    // 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
    der256 = upd("MDEwDQYJYIZIAWUDBAIBBQAEIA");

    return {
        sha224: msrcryptoSha("SHA-224", der224, h224, k256, 64, hashBlock, 224),
        sha256: msrcryptoSha("SHA-256", der256, h256, k256, 64, hashBlock, 256)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha256.hash256 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.sha256.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha256.sha256.finish();
        }

        return msrcryptoSha256.sha256.computeHash(p.buffer);

    };

    msrcryptoSha256.hash224 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.sha224.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha256.sha224.finish();
        }

        return msrcryptoSha256.sha224.computeHash(p.buffer);

    };

    operations.register("digest", "sha-224", msrcryptoSha256.hash224);
    operations.register("digest", "sha-256", msrcryptoSha256.hash256);
}

msrcryptoHashFunctions["sha-224"] = msrcryptoSha256.sha224;
msrcryptoHashFunctions["sha-256"] = msrcryptoSha256.sha256;
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

/* jshint -W016 */ /* allows bitwise operators */

/// <reference path="utilities.js" />

/// <dictionary>
///    msrcrypto,aes,mult,rcon,res,tmp,xor
/// </dictionary>

/// #endregion JSCop/JsHint

var msrcryptoBlockCipher = (function()  {

    var aesConstants,
    multByTwo,
    multByThree,
    multBy14,
    multBy13,
    multBy11,
    multBy9,
    sBoxTable,
    invSBoxTable,
    rConTable;

    return {

        /// <summary>Advanced Encryption Standard implementation per FIPS 197.</summary>
        aes: function ( /*@type(Array)*/ keyBytes) {

            // Set up the constants the first time we create an AES object only.
            if (!aesConstants) {
                aesConstants = msrcryptoUtilities.unpackData("AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4bGR8dExEXFQsJDw0DAQcFOzk/PTMxNzUrKS8tIyEnJVtZX11TUVdVS0lPTUNBR0V7eX99c3F3dWtpb21jYWdlm5mfnZORl5WLiY+Ng4GHhbu5v72zsbe1q6mvraOhp6Xb2d/d09HX1cvJz83DwcfF+/n//fPx9/Xr6e/t4+Hn5QADBgUMDwoJGBseHRQXEhEwMzY1PD86OSgrLi0kJyIhYGNmZWxvaml4e359dHdycVBTVlVcX1pZSEtOTURHQkHAw8bFzM/Kydjb3t3U19LR8PP29fz/+vno6+7t5Ofi4aCjpqWsr6qpuLu+vbS3srGQk5aVnJ+amYiLjo2Eh4KBm5idnpeUkZKDgIWGj4yJiquora6npKGis7C1tr+8ubr7+P3+9/Tx8uPg5ebv7Onqy8jNzsfEwcLT0NXW39zZ2ltYXV5XVFFSQ0BFRk9MSUpraG1uZ2RhYnNwdXZ/fHl6Ozg9Pjc0MTIjICUmLywpKgsIDQ4HBAECExAVFh8cGRoADhwSODYkKnB+bGJIRlRa4O788tjWxMqQnoyCqKa0utvVx8nj7f/xq6W3uZOdj4E7NScpAw0fEUtFV1lzfW9hraOxv5WbiYfd08HP5ev5901DUV91e2lnPTMhLwULGRd2eGpkTkBSXAYIGhQ+MCIslpiKhK6gsrzm6Pr03tDCzEFPXVN5d2VrMT8tIwkHFRuhr72zmZeFi9HfzcPp5/X7mpSGiKKsvrDq5Pb40tzOwHp0ZmhCTF5QCgQWGDI8LiDs4vD+1NrIxpySgI6kqri2DAIQHjQ6KCZ8cmBuREpYVjc5KyUPARMdR0lbVX9xY23X2cvF7+Hz/aepu7WfkYONAA0aFzQ5LiNoZXJ/XFFGS9Ddysfk6f7zuLWir4yBlpu7tqGsj4KVmNPeycTn6v3wa2ZxfF9SRUgDDhkUNzotIG1gd3pZVENOBQgfEjE8Kya9sKeqiYSTntXYz8Lh7Pv21tvMweLv+PW+s6SpioeQnQYLHBEyPyglbmN0eVpXQE3a18DN7uP0+bK/qKWGi5yRCgcQHT4zJClib3h1VltMQWFse3ZVWE9CCQQTHj0wJyqxvKumhYifktnUw87t4Pf6t7qtoIOOmZTf0sXI6+bx/GdqfXBTXklEDwIVGDs2ISwMARYbODUiL2RpfnNQXUpH3NHGy+jl8v+0ua6jgI2alwALFh0sJzoxWFNORXR/Ymmwu6atnJeKgejj/vXEz9LZe3BtZldcQUojKDU+DwQZEsvA3dbn7PH6k5iFjr+0qaL2/eDr2tHMx66luLOCiZSfRk1QW2phfHceFQgDMjkkL42Gm5Chqre81d7DyPny7+Q9NisgERoHDGVuc3hJQl9U9/zh6tvQzcavpLmyg4iVnkdMUVprYH12HxQJAjM4JS6Mh5qRoKu2vdTfwsn48+7lPDcqIRAbBg1kb3J5SENeVQEKFxwtJjswWVJPRHV+Y2ixuqesnZaLgOni//TFztPYenFsZ1ZdQEsiKTQ/DgUYE8rB3Nfm7fD7kpmEj761qKMACRIbJC02P0hBWlNsZX53kJmCi7S9pq/Y0crD/PXu5zsyKSAfFg0Ec3phaFdeRUyrormwj4adlOPq8fjHztXcdn9kbVJbQEk+NywlGhMIAebv9P3Cy9DZrqe8tYqDmJFNRF9WaWB7cgUMFx4hKDM63dTPxvnw6+KVnIeOsbijquzl/vfIwdrTpK22v4CJkpt8dW5nWFFKQzQ9Ji8QGQIL197FzPP64eiflo2Eu7KpoEdOVVxjanF4DwYdFCsiOTCak4iBvrespdLbwMn2/+TtCgMYES4nPDVCS1BZZm90faGos7qFjJee6eD78s3E39YxOCMqFRwHDnlwa2JdVE9GY3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7FlIJatUwNqU4v0CjnoHz1/t84zmCmy//hzSOQ0TE3unLVHuUMqbCIz3uTJULQvrDTgguoWYo2SSydluiSW2L0SVy+PZkhmiYFtSkXMxdZbaSbHBIUP3tudpeFUZXp42dhJDYqwCMvNMK9+RYBbizRQbQLB6Pyj8PAsGvvQMBE4prOpERQU9n3OqX8s/O8LTmc5asdCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA7Ta4q9bDI67s8g1OZYRcrBH66d9Ym4WkUY1UhDH2NAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuN", 256, false);
                multByTwo = aesConstants[0];
                multByThree = aesConstants[1];
                multBy14 = aesConstants[2];
                multBy13 = aesConstants[3];
                multBy11 = aesConstants[4];
                multBy9 = aesConstants[5];
                sBoxTable = aesConstants[6];
                invSBoxTable = aesConstants[7];
                rConTable = aesConstants[8];
            }

            var blockSize = 128,
                keyLength,
                nK,
                nB = 4,
                nR,
                key;

            switch (keyBytes.length * 8) {

                case 128:
                    keyLength = 128;
                    nK = 4;
                    nR = 10;
                    break;

                case 192:
                    keyLength = 192;
                    nK = 6;
                    nR = 12;
                    break;

                case 256:
                    keyLength = 256;
                    nK = 8;
                    nR = 14;
                    break;

                default:
                    throw new Error("Unsupported keyLength");
            }

            var shiftRows = function (a) {
                var tmp = a[1]; a[1] = a[5]; a[5] = a[9]; a[9] = a[13]; a[13] = tmp;
                tmp = a[2]; a[2] = a[10]; a[10] = tmp;
                tmp = a[6]; a[6] = a[14]; a[14] = tmp;
                tmp = a[15]; a[15] = a[11]; a[11] = a[7]; a[7] = a[3]; a[3] = tmp;
            };

            var invShiftRows = function (a) {
                var tmp = a[13]; a[13] = a[9]; a[9] = a[5]; a[5] = a[1]; a[1] = tmp;
                tmp = a[10]; a[10] = a[2]; a[2] = tmp;
                tmp = a[14]; a[14] = a[6]; a[6] = tmp;
                tmp = a[3]; a[3] = a[7]; a[7] = a[11]; a[11] = a[15]; a[15] = tmp;
            };

            var mixColumns = function (state) {
                /// <summary>Operates on the state column by column, performing a multiplication by x^4 + 1 in GF(2^8)</summary>
                /// <param name="state" type="Array"> the current state (length 16)</param>
                /// <returns type="Array">The mixed state</returns>
                var a = state[0], b = state[1], c = state[2], d = state[3],
                    e = state[4], f = state[5], g = state[6], h = state[7],
                    i = state[8], j = state[9], k = state[10], l = state[11],
                    m = state[12], n = state[13], o = state[14], p = state[15];

                state[0] = multByTwo[a] ^ multByThree[b] ^ c ^ d;
                state[1] = a ^ multByTwo[b] ^ multByThree[c] ^ d;
                state[2] = a ^ b ^ multByTwo[c] ^ multByThree[d];
                state[3] = multByThree[a] ^ b ^ c ^ multByTwo[d];
                state[4] = multByTwo[e] ^ multByThree[f] ^ g ^ h;
                state[5] = e ^ multByTwo[f] ^ multByThree[g] ^ h;
                state[6] = e ^ f ^ multByTwo[g] ^ multByThree[h];
                state[7] = multByThree[e] ^ f ^ g ^ multByTwo[h];
                state[8] = multByTwo[i] ^ multByThree[j] ^ k ^ l;
                state[9] = i ^ multByTwo[j] ^ multByThree[k] ^ l;
                state[10] = i ^ j ^ multByTwo[k] ^ multByThree[l];
                state[11] = multByThree[i] ^ j ^ k ^ multByTwo[l];
                state[12] = multByTwo[m] ^ multByThree[n] ^ o ^ p;
                state[13] = m ^ multByTwo[n] ^ multByThree[o] ^ p;
                state[14] = m ^ n ^ multByTwo[o] ^ multByThree[p];
                state[15] = multByThree[m] ^ n ^ o ^ multByTwo[p];
            };

            var invMixColumns = function (state) {
                /// <summary>Operates on the state column by column, performing a multiplication by x^4 + 1 in GF(2^8)</summary>
                /// <param name="state" type="Array"> the current state (length 16)</param>
                /// <returns type="Array">The mixed state</returns>
                var a = state[0], b = state[1], c = state[2], d = state[3],
                    e = state[4], f = state[5], g = state[6], h = state[7],
                    i = state[8], j = state[9], k = state[10], l = state[11],
                    m = state[12], n = state[13], o = state[14], p = state[15];

                state[0] = multBy14[a] ^ multBy11[b] ^ multBy13[c] ^ multBy9[d];
                state[1] = multBy9[a] ^ multBy14[b] ^ multBy11[c] ^ multBy13[d];
                state[2] = multBy13[a] ^ multBy9[b] ^ multBy14[c] ^ multBy11[d];
                state[3] = multBy11[a] ^ multBy13[b] ^ multBy9[c] ^ multBy14[d];
                state[4] = multBy14[e] ^ multBy11[f] ^ multBy13[g] ^ multBy9[h];
                state[5] = multBy9[e] ^ multBy14[f] ^ multBy11[g] ^ multBy13[h];
                state[6] = multBy13[e] ^ multBy9[f] ^ multBy14[g] ^ multBy11[h];
                state[7] = multBy11[e] ^ multBy13[f] ^ multBy9[g] ^ multBy14[h];
                state[8] = multBy14[i] ^ multBy11[j] ^ multBy13[k] ^ multBy9[l];
                state[9] = multBy9[i] ^ multBy14[j] ^ multBy11[k] ^ multBy13[l];
                state[10] = multBy13[i] ^ multBy9[j] ^ multBy14[k] ^ multBy11[l];
                state[11] = multBy11[i] ^ multBy13[j] ^ multBy9[k] ^ multBy14[l];
                state[12] = multBy14[m] ^ multBy11[n] ^ multBy13[o] ^ multBy9[p];
                state[13] = multBy9[m] ^ multBy14[n] ^ multBy11[o] ^ multBy13[p];
                state[14] = multBy13[m] ^ multBy9[n] ^ multBy14[o] ^ multBy11[p];
                state[15] = multBy11[m] ^ multBy13[n] ^ multBy9[o] ^ multBy14[p];
            };

            var xorWord = function (a, b) {
                return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
            };

            var addRoundKey = function (/*@type(Array)*/state, keySchedule, offset) {
                for (var i = 0 ; i < state.length ; i += 1) {
                    state[i] ^= keySchedule[i + offset];
                }
            };

            var rotWord = function (/*@type(Array)*/word) {
                var a = word[0];
                word[0] = word[1]; word[1] = word[2]; word[2] = word[3]; word[3] = a;
            };

            var subWord = function (/*@type(Array)*/word) {
                for (var i = 0 ; i < word.length ; i += 1) {
                    word[i] = sBoxTable[word[i]];
                }
            };

            var invSubWord = function (/*@type(Array)*/word) {
                for (var i = 0 ; i < word.length ; i += 1) {
                    word[i] = invSBoxTable[word[i]];
                }
            };

            var getWord = function (tab, i) {
                return [tab[4 * i], tab[4 * i + 1], tab[4 * i + 2], tab[4 * i + 3]];
            };

            var setWord = function (/*@type(Array)*/left, /*@type(Array)*/right, indexL, indexR) {
                left[4 * indexL] = right[4 * indexR];
                left[4 * indexL + 1] = right[4 * indexR + 1];
                left[4 * indexL + 2] = right[4 * indexR + 2];
                left[4 * indexL + 3] = right[4 * indexR + 3];
            };

            var expandKey = function (key) {
                var temp, res = [], i = 0;
                while (i < 4 * nK) {
                    res.push(key[i++]);
                }

                i = nK;
                while (i < nB * (nR + 1)) {
                    temp = getWord(res, i - 1);
                    if (i % nK === 0) {
                        var index = i / nK;
                        var rcon = [rConTable[index], 0, 0, 0];
                        rotWord(temp);
                        subWord(temp);
                        temp = xorWord(temp, rcon);
                    } else if (nK > 6 && i % nK === 4) {
                        subWord(temp);
                    }
                    var newWord = xorWord(getWord(res, i - nK), temp);
                    setWord(res, newWord, i, 0);
                    i += 1;
                }
                return res;
            };

            key = expandKey(keyBytes);

            return {

                encrypt: function (dataBytes) {
                    var state = dataBytes,
                        round;

                    addRoundKey(state, key, 0);
                    for (round = 1 ; round <= nR - 1 ; round += 1) {
                        subWord(state);
                        shiftRows(state);
                        mixColumns(state);
                        addRoundKey(state, key, 4 * round * nB);
                    }
                    subWord(state);
                    shiftRows(state);
                    addRoundKey(state, key, 4 * nR * nB);

                    return state;
                },

                decrypt: function (dataBytes) {
                    var state = dataBytes,
                        round;

                    addRoundKey(state, key, 4 * nR * nB);
                    for (round = nR - 1 ; round >= 1 ; round -= 1) {
                        invShiftRows(state);
                        invSubWord(state);
                        addRoundKey(state, key, 4 * round * nB);
                        invMixColumns(state);
                    }
                    invShiftRows(state);
                    invSubWord(state);
                    addRoundKey(state, key, 0);

                    return state;
                },

                clear: function () {
                    // Reset the state
                },

                keyLength: keyLength,

                blockSize: blockSize

            };
        }

    };

})();
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
///     Cbc,msrcrypto,res
/// </dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoPadding = msrcryptoPadding || {};

msrcryptoPadding.pkcsv7 = function (blockSize) {

    function pad(messageBlocks) {
        /// <signature>
        ///     <summary>Apply PKCS7 padding to message</summary>
        ///     <param name="messageBlocks" type="Array">An array of blocks to pad</param> <
        /// </signature>

        var lastIndex = messageBlocks.length - 1 >= 0 ? messageBlocks.length - 1 : 0,
            lastBlock = messageBlocks[lastIndex],
            lastBlockLength = lastBlock.length,
            createNewBlock = (lastBlockLength === blockSize);

        if (createNewBlock) {
            var newBlock = [], i;
            for (i = 0 ; i < blockSize; i += 1) {
                newBlock.push(blockSize);
            }
            messageBlocks.push(newBlock);
        } else {
            var byteToAdd = (blockSize - lastBlockLength) & 0xff;
            while (lastBlock.length !== blockSize) {
                lastBlock.push(byteToAdd);
            }
        }

    }

    function unpad(messageBytes) {
        /// <signature>
        ///     <summary>Remove PKCS7 padding from the message</summary>
        ///     <param name="messageBytes" type="Array"></param>
        ///     <returns type="Boolean">True for legal padding. False if not.</returns>
        /// </signature>

        var verified = true;

        // Verify the cipher text is an increment of block length
        if (messageBytes.length % blockSize !== 0) {
            verified = false;
        }

        // Get the last block
        var lastBlock = messageBytes.slice(-blockSize);

        // Get value of the last element in the block
        // This will be the number of padding bytes on the end if the
        // message was decrypted correctly.
        var padLen = lastBlock[lastBlock.length - 1];        

        for (var i = 0; i < blockSize; i++) {
            var isPaddingElement = (blockSize - i <= padLen);
            var isCorrectValue = (lastBlock[i] === padLen);
            verified = (isPaddingElement ? isCorrectValue : true) && verified;
        }

        var trimLen = verified ? padLen : 0;

        messageBytes.length -= trimLen;

        return verified;
    }

    return {
        pad: pad,
        unpad: unpad
    };

};

var msrcryptoCbc = function (blockCipher) {

    var blockSize = blockCipher.blockSize / 8;

    var paddingScheme = msrcryptoPadding.pkcsv7(blockSize);

    // Merges an array of block arrays into a single byte array
    var mergeBlocks = function (/*@type(Array)*/tab) {
        var res = [], i, j;
        for (i = 0 ; i < tab.length; i += 1) {
            var block = tab[i];
            for (j = 0 ; j < block.length; j += 1) {
                res.push(block[j]);
            }
        }
        return res;
    };

    // Breaks an array of bytes into an array of block size arrays of bytes
    function getBlocks(dataBytes) {

        var blocks = [];

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(dataBytes);

        var blockCount = Math.floor(mBuffer.length / blockSize);

        for (var i = 0; i < blockCount; i++) {
            blocks.push(mBuffer.slice(i * blockSize, (i + 1) * blockSize));
        }

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(blockCount * blockSize);

        return blocks;
    }

    function encryptBlocks(blocks) {

        var result = [],
            toEncrypt;

        for (var i = 0; i < blocks.length; i++) {
            toEncrypt = msrcryptoUtilities.xorVectors(mIvBytes, blocks[i]);
            result.push(blockCipher.encrypt(toEncrypt));
            mIvBytes = result[i];
        }

        return result;
    }

    function decryptBlocks(blocks) {

        var result = [],
            toDecrypt,
            decrypted;

        for (var i = 0 ; i < blocks.length; i += 1) {
            toDecrypt = blocks[i].slice(0, blocks[i].length);
            decrypted = blockCipher.decrypt(toDecrypt);
            result.push(msrcryptoUtilities.xorVectors(mIvBytes, decrypted));
            mIvBytes = blocks[i];
        }

        return result;
    }

    function clearState() {
        mBuffer = [];
        mResultBuffer = [];
        mIvBytes = null;
    }

    var mBuffer = [],
        mResultBuffer = [],
        mIvBytes;

    return {

        init: function (ivBytes) {

            if (ivBytes.length !== blockSize) {
                throw new Error("Invalid iv size");
            }

            mIvBytes = ivBytes.slice();
        },

        // Does a full encryption of the input
        encrypt: function (plainBytes) {
            /// <summary>perform the encryption of the plain text message</summary>
            /// <param name="plainBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processEncrypt(plainBytes);

            return this.finishEncrypt();
        },

        // Encrypts full blocks of streamed input
        processEncrypt: function (plainBytes) {

            var result = encryptBlocks(getBlocks(plainBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Call when done streaming input
        finishEncrypt: function () {

            var blocks = mBuffer.length === 1 ? [[mBuffer[0]]] : [mBuffer];

            paddingScheme.pad(blocks);

            var result = mResultBuffer.concat(mergeBlocks(encryptBlocks(blocks)));

            clearState();

            return result;
        },

        // Does a full decryption and returns the result
        decrypt: function (/*@type(Array)*/cipherBytes) {
            /// <summary>perform the decryption of the encrypted message</summary>
            /// <param name="encryptedBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processDecrypt(cipherBytes);

            return this.finishDecrypt();
        },

        // Decrypts full blocks of streamed data
        processDecrypt: function (cipherBytes) {

            var result = decryptBlocks(getBlocks(cipherBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Called to finalize streamed decryption
        finishDecrypt: function () {

            var result = mResultBuffer;

            // Strip the padding.
            var verified = paddingScheme.unpad(result);

            clearState();

            return result;
        }

    };
};

var cbcInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoCbc.workerEncrypt = function (p) {

        var result;

        if (!cbcInstance) {
            cbcInstance = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstance.init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstance.processEncrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstance.finishEncrypt();
            cbcInstance = null;
            return result;
        }

        result = cbcInstance.encrypt(p.buffer);
        cbcInstance = null;
        return result;
    };

    msrcryptoCbc.workerDecrypt = function (p) {

        var result;

        if (!cbcInstance) {
            cbcInstance = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstance.init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstance.processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstance.finishDecrypt();
            cbcInstance = null;
            return result;
        }

        result = cbcInstance.decrypt(p.buffer);
        cbcInstance = null;
        return result;
    };

    msrcryptoCbc.generateKey = function (p) {

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

    msrcryptoCbc.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);

        p.algorithm.length = keyObject.k.length * 8;

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

    msrcryptoCbc.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "aes-cbc", msrcryptoCbc.importKey);
    operations.register("exportKey", "aes-cbc", msrcryptoCbc.exportKey);
    operations.register("generateKey", "aes-cbc", msrcryptoCbc.generateKey);
    operations.register("encrypt", "aes-cbc", msrcryptoCbc.workerEncrypt);
    operations.register("decrypt", "aes-cbc", msrcryptoCbc.workerDecrypt);
}
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

/* jshint -W016 */

/// <reference path="utilities.js" />
/// <reference path="aes.js" />

/// <dictionary>msrcrypto, utils, xor, res, csrc, nist, nistpubs, prng</dictionary>

/// #endregion JSCop/JsHint

/* @constructor */ function MsrcryptoPrng() {
    /// <summary>Pseudo Random Number Generator function/class.</summary>
    /// <remarks>This is the PRNG engine, not the entropy collector.
    /// The engine must be initialized with adequate entropy in order to generate cryptographically secure
    /// random numbers. It is hard to get entropy, but see the entropy functoin/class for the entropy gatherer.
    /// This is not an object instantiation, but the definition of the object. The actual
    /// object must be instantiated somewhere else as needed.
    /// </remarks>

    if (!(this instanceof MsrcryptoPrng)) {
        throw new Error("create MsrcryptoPrng object with new keyword");
    }

    // Fallback for browsers which do not implements crypto API yet
    // implementation of http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf.
    // Use AES-256 in CTR mode of operation as defined in Section 10.2.1.
    var initialized = false;

    // Internal state definitions are as follows.
    // v : internal variable that will ultimately be the random output
    // key: the AES key (256 bits)
    // keyLen: the AES key length in bytes
    // reseedCounter: the number of requests for pseudorandom bits since instantiation/reseeding
    // reseedInterval: Maximum number of generate calls per seed or reseed. SP800-90A says 2^48 for AES, we use 2^24.
    var key;
    var v;
    var keyLen;
    var seedLen;
    var reseedCounter = 1;
    var reseedInterval = 1 << 24;

    // Initialize this instance (constructor like function)
    initialize();

    function addOne(counter) {
        /// <summary>Adds one to a big integer represented in an array (the first argument).</summary>
        /// <param name="counter" counter="Array">The counter byte array to add one to encoded in big endian; index 0 is the MSW.</param>
        var i;
        for (i = counter.length - 1; i >= 0; i -= 1) {
            counter[i] += 1;
            if (counter[i] >= 256) {
                counter[i] = 0;
            }
            if (counter[i]) {
                break;
            }
        }
    }

    function initialize() {
        /// <summary>Instantiate the PRNG with given entropy and personalization string.</summary>
        /// <param name="entropy" type="Array">Array of bytes obtained from the source of entropy input.</param>
        /// <param name="personalizationString" type="Array">Optional application-provided personalization string.</param>
        key = msrcryptoUtilities.getVector(32);
        v = msrcryptoUtilities.getVector(16);            // AES block length
        keyLen = 32;
        seedLen = 48;       // From SP800-90A, section 10.2.1 as of 2014.
        reseedCounter = 1;
    }

    function reseed(entropy,/*@optional*/ additionalEntropy) {
        /// <summary>Reseed the PRNG with additional entropy.</summary>
        /// <param name="entropy" type="Array">Input entropy.</param>
        /// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>
        additionalEntropy = additionalEntropy || [0];
        if (additionalEntropy.length > seedLen) {
            throw new Error("Incorrect entropy or additionalEntropy length");
        }
        additionalEntropy = additionalEntropy.concat(msrcryptoUtilities.getVector(seedLen - additionalEntropy.length));

        // Process the entropy input in blocks with the same additional entropy.
        // This is equivalent to the caller chunking entropy in blocks and calling this function for each chunk.
        entropy = entropy.concat(msrcryptoUtilities.getVector((seedLen - (entropy.length % seedLen)) % seedLen));
        for (var i = 0; i < entropy.length; i += seedLen) {
            var seedMaterial = msrcryptoUtilities.xorVectors(entropy.slice(i, i + seedLen), additionalEntropy);
            update(seedMaterial);
        }
        reseedCounter = 1;
    }

    function update(providedData) {
        /// <summary>Add the providedData to the internal entropy pool, and update internal state.</summary>
        /// <param name="providedData" type="Array">Input to add to the internal entropy pool.</param>
        var temp = [];
        var blockCipher = new msrcryptoBlockCipher.aes(key);
        while (temp.length < seedLen) {
            addOne(v);
            var toEncrypt = v.slice(0, 16);
            var outputBlock = blockCipher.encrypt(toEncrypt); // AES-256
            temp = temp.concat(outputBlock);
        }
        temp = msrcryptoUtilities.xorVectors(temp, providedData);
        key = temp.slice(0, keyLen);
        v = temp.slice(keyLen);
    }

    function generate(requestedBytes,/*@optional*/ additionalInput) {
        /// <summary>Generate pseudo-random bits, and update the internal PRNG state.</summary>
        /// <param name="requestedBytes" type="Number">Number of pseudorandom bytes to be returned.</param>
        /// <param name="additionalInput" type="Array">Application-provided additional input array (optional).</param>
        /// <returns>Generated pseudorandom bytes.</returns>
        if (requestedBytes >= 65536) {
            throw new Error("too much random requested");
        }
        if (reseedCounter > reseedInterval) {
            throw new Error("Reseeding is required");
        }
        if (additionalInput && additionalInput.length > 0) {
            while (additionalInput.length < seedLen) {
                additionalInput = additionalInput.concat(msrcryptoUtilities.getVector(seedLen - additionalInput.length));
            }
            update(additionalInput);
        } else {
            additionalInput = msrcryptoUtilities.getVector(seedLen);
        }
        var temp = [];
        var blockCipher = new msrcryptoBlockCipher.aes(key);
        while (temp.length < requestedBytes) {
            addOne(v);
            var toEncrypt = v.slice(0, v.length);
            var outputBlock = blockCipher.encrypt(toEncrypt);
            temp = temp.concat(outputBlock);
        }
        temp = temp.slice(0, requestedBytes);
        update(additionalInput);
        reseedCounter += 1;
        return temp;
    }

    return {
        reseed: reseed,
        /// <summary>Reseed the PRNG with additional entropy.</summary>
        /// <param name="entropy" type="Array">Input entropy.</param>
        /// <param name="additionalEntropy" type="Array">Optional additional entropy input.</param>

        init: function (entropy,/*@optional*/ personalization) {
            /// <summary>Initialize the PRNG by seeing with entropy and optional input data.</summary>
            /// <param name="entropy" type="Array">Input entropy.</param>
            /// <param name="personalization" type="Array">Optional input.</param>
            if (entropy.length < seedLen) {
                throw new Error("Initial entropy length too short");
            }
            initialize();
            reseed(entropy, personalization);
            initialized = true;
        },
        getBytes: function (length, /*@optional*/ additionalInput) {
            if (!initialized) {
                throw new Error("can't get randomness before initialization");
            }
            return generate(length, /*@optional*/ additionalInput);
        },
        getNonZeroBytes: function (length, additionalInput) {
            if (!initialized) {
                throw new Error("can't get randomness before initialization");
            }
            var result = [], buff;
            while (result.length < length) {
                buff = generate(length, additionalInput);
                for (var i = 0 ; i < buff.length; i += 1) {
                    if (buff[i] !== 0) {
                        result.push(buff[i]);
                    }
                }
            }
            return result.slice(0, length);
        }
    };
}

// This is the PRNG object per instantiation, including one per worker.
// The instance in the main thread is used to seed the instances in workers.
// TODO: Consider combining the entropy pool in the main thread with the PRNG instance in the main thread.
/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var msrcryptoPseudoRandom = new MsrcryptoPrng();
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>
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
/* global arrayHelper */
/* global MsrcryptoPrng */

/* jshint -W016 */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="arrayHelper.js" />
/// <reference path="jsCopDefs.js" />

/// <dictionary>arr,msrcrypto,Prng,req,res,mozilla,polyfill,PRNGs,redirectlocale,redirectslug</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

function MsrcryptoEntropy() {
    /// <summary>Opportunistic entropy collector.</summary>
    /// <remarks>See E.Stark, M.Hamburg, D.Boneh, "Symmetric Cryptography in Javascript", ACSAC, 2009.
    /// This is not an object instantiation, but the definition of the object. The actual
    /// object must be instantiated somewhere else as needed.
    /// If window.{crypto,msCrypto}.getRandomValues() function is present, do not register mouse and JS load events,
    /// because they slow down the execution, and it is not clear how much they contributed over and above
    /// a cryptographic random value.
    /// </remarks>

    var poolLength = 48;      // In bytes, from SP800-90A, Section 10.2.1. See random.js for constraints.
    var collectorPool = [];
    var collectorPoolLength = 128;  // Bytes to collect before stopping; collectors are restartable.
    var collectorsRegistered = 0;
    var entropyPoolPrng = new MsrcryptoPrng();
    var initialized = false;
    var cryptographicPRNGPresent = false;
    var headerList = ["Cookie", "RedirectUri", "ETag", "x-ms-client-antiforgery-id", "x-ms-client-request-id", "x-ms-client-session-id", "SubscriptionPool"];

    function collectEntropy() {
        /// <summary>Initialize the internal pool with as much randomness as one can get in JS.
        /// In the worst case, there is zero bits of entropy.</summary>

        var i, pool = [];

        // In Safari, as of r39510, reportedly, Math.random() is cryptographically secure on Mac and Windows.
        // Even if it isn't, mix that in via XORing into the existing array.
        // According to ECMA, Math.random() returns [0,1). Thus, multiply it by 256 to get [0,256).
        for (i = 0; i < poolLength; i += 1) {
            pool[i] = Math.floor(Math.random() * 256);
        }

        // For browsers that implement window.crypto.getRandomValues, use it.
        var prngCrypto = window.crypto || window.msCrypto;       // WARNING: !!! Do not put this in a function (remember polyfill) !!!
        if (prngCrypto && typeof prngCrypto.getRandomValues === "function") {
            if (window.Uint8Array) {
                var res = new window.Uint8Array(poolLength);
                prngCrypto.getRandomValues(res);
                pool = pool.concat(Array.apply(null, /*@static_cast(Array)*/res));
                cryptographicPRNGPresent = true;
            }
        }

        // Read HTTP headers that contain entropy and reseed the entropy pool
        var req = new XMLHttpRequest();
        for (i = 0; i < headerList.length; i += 1) {
            try {
                var header = req.getResponseHeader(headerList[i]);
                if (header) {
                    var arr = msrcryptoUtilities.stringToBytes(header);
                    pool = pool.concat(arr);
                }
            }
            catch (err) {
                // Ignore any header I can't get
            }
        }

        if (!cryptographicPRNGPresent) {
            // Add any data in the collector pool, empty the collector pool, and restart collectors.
            pool = pool.concat(collectorPool.splice(0, collectorPool.length));
            collectors.startCollectors();
        }

        // Worst case: initialized with Math.random()
        initialized ? entropyPoolPrng.reseed(pool) : entropyPoolPrng.init(pool);
        initialized = true;
    }

    function updatePool(entropyData) {
        /// <summary>Collect the incoming data into the pool, and
        /// empty the pool into the entropy PRNG state when the pool is full.
        /// This function is additive entropy, only; this is not the main source of entropy.</summary>
        /// <param name="entropyData" type="Array">Entropy input.</param>
        for (var i = 0; i < entropyData.length; ++i) {
            collectorPool.push(entropyData[i]);
        }
        if (collectorPool.length >= collectorPoolLength) {
            // Stop the collectors (performance reasons).
            // The real entropy does not come from the event callbacks: these are at best uniquifiers.
            collectors.stopCollectors();
        }
    }

    // Event listeners are not supported in IE 8.
    // See https://developer.mozilla.org/en-US/docs/Web/API/EventTarget.addEventListener?redirectlocale=en-US&redirectslug=DOM%2FEventTarget.addEventListener
    // to add IE8 support.
    // BUGBUG: For the time being, I am not bothering with IE8 support - fix this.
    var collectors = (function () {
        return {
            startCollectors: function () {
                if (!this.collectorsRegistered) {
                    if (window.addEventListener) {
                        window.addEventListener("mousemove", this.MouseEventCallBack, true);
                        window.addEventListener("load", this.LoadTimeCallBack, true);
                    } else if (document.attachEvent) {
                        document.attachEvent("onmousemove", this.MouseEventCallBack);
                        document.attachEvent("onload", this.LoadTimeCallBack);
                    } else {
                        throw new Error("Can't attach events for entropy collection");
                    }

                    this.collectorsRegistered = 1;
                }
            },
            stopCollectors: function () {
                if (this.collectorsRegistered) {
                    if (window.removeEventListener) {
                        window.removeEventListener("mousemove", this.MouseEventCallBack, 1);
                        window.removeEventListener("load", this.LoadTimeCallBack, 1);
                    } else if (window.detachEvent) {
                        window.detachEvent("onmousemove", this.MouseEventCallBack);
                        window.detachEvent("onload", this.LoadTimeCallBack);
                    }

                    this.collectorsRegistered = 0;
                }
            },
            MouseEventCallBack: function (eventData) {
                /// <summary>Add the mouse coordinates to the entropy pool and the Date.</summary>
                /// <param name="eventData">Event data with mouse information.</param>
                var d = (new Date()).valueOf();
                var x = eventData.x || eventData.clientX || eventData.offsetX || 0;
                var y = eventData.y || eventData.clientY || eventData.offsetY || 0;
                var arr = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff,
                        x & 0x0ff, (x >> 8) & 0x0ff, y & 0x0ff, (y >> 8) & 0x0ff];

                updatePool(arr);
            },
            LoadTimeCallBack: function () {
                /// <summary>Add date to the entropy pool.</summary>
                /// <remarks>Date valueOf() returns milliseconds since midnight 1/1/1970 UTC in a 32 bit integer</remarks>
                var d = (new Date()).valueOf();
                var dateArray = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff];

                updatePool(dateArray);
            }
        };
    })();

    return {
        init: function () {
            collectEntropy();

            // Register collectors
            if (!cryptographicPRNGPresent && !collectorsRegistered) {
                try {
                    collectors.startCollectors();
                }
                catch (e) {
                    // Ignore errors instead of trying to do something browser specific. That is not tractable.
                    // It is expected that the calling program injects most of the entropy or the build-in collectors
                    // contributes rather than registered events.
                }
            }
        },

        reseed: function (entropy) {
            /// <summary>Mix in entropy into the pool.</summary>
            /// <param name="entropy" type="Array">Entropy to mix in.</param>
            entropyPoolPrng.reseed(entropy);
        },

        read: function (length) {
            /// <summary>Read entropy from the entropy pool. This function fails if there isn't enough entropy.</summary>
            /// <param name="length" type="Number">Number of bytes of requested entropy.</param>
            /// <returns type="Array">Entropy if there is enough in the pool, or undefined if there isn't enough entropy.</returns>
            if (!initialized) {
                throw new Error("Entropy pool is not initialized.");
            }

            var ret = entropyPoolPrng.getBytes(length);

            // TODO: Do this async?
            //       No, another call may come through before the pool is reseeded.
            //       All PRNGs have their own running state anyhow. They can reseed themselves in async mode, if need be.
            collectEntropy();

            return ret;
        }
    };
}
///#source 1 1 /scripts/subtle/head.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

/// #region JSCop/JsHint
/* global arrayHelper */
/* global asyncMode: true */
/* global createProperty */
/* global defined */
/* global msrcryptoUtilities */
/* global msrcryptoWorker */
/* global msrcryptoPseudoRandom */
/* global fprngEntropyProvided: true */
/* global runningInWorkerInstance */
/* global scriptUrl */
/* global setterSupport */
/* global webWorkerSupport */
/* global operations */
/* jshint -W098 */
/* W098 is 'defined but not used'. We have not-yet-implemented apis stubbed out. */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="worker.js" />
/// <reference path="utilities.js" />

/// These are terms that JSCop thinks are misspelled, so we have to add them to its dictionary
/// <dictionary>
///    concat, msrcrypto, onabort, oncomplete, onerror, onmessage, onprogress, Params, prng,
///    syncWorker, webworker, webworkers, obj
/// </dictionary>

//  JSCop cannot figure out the types correctly
/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoSubtle;

// This code is not used in web worker instance.
if (!runningInWorkerInstance) {

    msrcryptoSubtle = (function() {
///#source 1 1 /scripts/subtle/promises.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

// If no native Promise support add ours
if (!window.Promise) {

    window.Promise = function (executor, id) {
        /// <summary>
        /// Creates a new promise.
        /// </summary>
        /// <param name="executor" type="function">A function that takes two parameters: function(resolved, rejected){...}</param>
        /// <returns type="Promise">A new Promise object</returns>

        if (!(this instanceof Promise)) {
            throw new Error("use 'new' keyword with Promise constructor");
        }

        var successResult = null,
            failReason = null,
            thenResolved = [],
            thenRejected = [],
            rejectThenPromise = [],
            resolveThenPromise = [];

        this.then = function (onCompleted, onRejected) {

            var thenFunctionResult;

            // If we already have a result because resolveFunction was synchronous,
            // then just call onCompleted with the result.
            if (successResult) {
                thenFunctionResult = onCompleted(successResult.result);

                if (thenFunctionResult && thenFunctionResult.then) {
                    return thenFunctionResult;
                }

                // Create a new promise; resolve with the result;
                // return the resolved promise.
                return Promise.resolve(thenFunctionResult);
            }

            // If we already have a fail reason from a rejected promise
            if (failReason) {
                thenFunctionResult = onRejected ? onRejected(failReason.result) : failReason.result;

                if (thenFunctionResult && thenFunctionResult.then) {
                    return thenFunctionResult;
                }

                // Create a new promise; reject with the result;
                // return the resolved promise.
                return Promise.resolve(thenFunctionResult);
            }

            // If we do not have a result, store the onCompleted/onRejected functions
            // to call when we do get a result.
            thenResolved.push(onCompleted);
            if (onRejected) {
                thenRejected.push(onRejected);
            }

            // Return a new promise object. This will allow chaining with then/catch().
            return new Promise(function (resolve, reject) {
                resolveThenPromise.push(resolve);
                rejectThenPromise.push(reject);
            });
        }

        this["catch"] = function (onRejected) {

            var catchFunctionResult;

            // If we already have a result because resolveFunction was synchronous,
            // then just call onRejected with the result.
            if (failReason) {
                catchFunctionResult = onRejected(failReason.result);

                if (catchFunctionResult && catchFunctionResult.then) {
                    return catchFunctionResult;
                }

                return Promise.resolve(catchFunctionResult);
            }

            // If we do not have a result, store the onRejected function
            // to call when we do get a result.
            thenRejected.push(onRejected);

            // Return a new promise object. This will allow chaining with then/catch().
            return new Promise(function (resolve, reject) {
                resolveThenPromise.push(resolve);
                rejectThenPromise.push(reject);
            });
        }

        var resolve = function (param) {
            /// <summary>
            /// Called by the executor function when the function has succeeded.
            /// </summary>
            /// <param name="param">A result value that will be passed to the then() function.</param>

            // Call each attached Then function with the result
            for (var i = 0; i < thenResolved.length; i++) {

                var result = thenResolved[i](param);

                // If the result of the then() function is a Promise,
                // set then() to call the chained resolve function.
                if (result && result.then) {
                    result.then(resolveThenPromise[i]);

                } else {

                    // If a then() promise was chained to this promise, call its resolve
                    // function.
                    if (resolveThenPromise[i]) {
                        resolveThenPromise[i](result);
                    }
                }
            }

            // If the onCompleted function has not yet been assigned, store the result.
            successResult = { result: param };

            return;
        }

        function reject(param) {

            // Call each catch function on this promise
            for (var i = 0; i < thenRejected.length; i++) {

                var reason = thenRejected[i](param);

                // If the result of the catch() function is a Promise,
                // set then() to call the chained resolve function.
                if (reason && reason.then) {
                    reason.then(resolveThenPromise[i], rejectThenPromise[i]);

                } else {
                    if (resolveThenPromise[i]) {
                        resolveThenPromise[i](reason);
                    }
                }
            }

            // If the onCompleted function has not yet been assigned, store the result.
            failReason = { result: param };

            return;
        };

        // Call the executor function passing the resolve & reject functions of 
        // this instance.

        executor(resolve, reject);

        return;
    }

    //#region static methods

    window.Promise.all = function (promiseArray) {
        /// <summary>
        /// Joins two or more promises and returns only when all the specified promises have completed or been rejected. 
        /// </summary>
        /// <param name="promiseArray" type="Array">Array of promises.</param>
        /// <returns type="Promise">Returns a Promise.</returns>

        var results = [],
            resultCount = 0;

        //  Generates a then function for each promise
        function then(index, resolve) {

            return function (result) {

                // We want the results to have the same results index as it was passed in.
                results[index] = result;

                // If all of the promises have returned results, call the resolve function
                // with the results array.
                if (++resultCount == promiseArray.length) {
                    resolve(results);
                }
            }
        }

        // Create a new Promise to return. It's resolve function will call then()
        // on each promise in the arguments list.
        var promiseAll = new Promise(

            function (resolve, reject) {

                for (var i = 0; i < promiseArray.length; i++) {

                    promiseArray[i].then(then(i, resolve));

                    // If a promise fails, return the reason
                    promiseArray[i]["catch"](function (reason) { reject(reason); });
                }
            });

        return promiseAll;
    };

    window.Promise.race = function (promiseArray) {
        /// <summary>
        /// Creates a new promise that will resolve or reject with the same result value as the first promise to resolve or reject among the passed in arguments. 
        /// </summary>
        /// <param name="promises" type="Array">Required. One or more promises.</param>
        /// <returns type="Promise">Result of first promise to resolve or fail.</returns>

        var resolved = false;

        //  Generates a then function for each promise
        function then(resolveFunction) {

            return function (result) {

                // When the first promise succeeds/fails, return the answer and ignore the rest.
                if (!resolved) {
                    resolved = true;
                    resolveFunction(result);
                }
            }
        }

        // Create a new Promise to return. It's resolve function will call then()
        // on each promise in the arguments list.
        var promiseRace = new Promise(

            function (resolve, reject) {

                for (var i = 0; i < promiseArray.length; i++) {
                    promiseArray[i].then(then(resolve), then(reject));
                }
            });

        return promiseRace;
    };

    window.Promise.reject = function (rejectReason) {
        /// <summary>
        /// Creates a new rejected promise with a result equal to the passed in argument. 
        /// </summary>
        /// <param name="rejectReason" type="">Required. The reason why the promise was rejected.</param>
        /// <returns type=""></returns>

        return new Promise(
            function (resolve, reject) {
                reject(rejectReason);
            });
    };

    window.Promise.resolve = function (resolveResult) {
        /// <summary>
        /// Creates a new resolved promise with a result equal to its argument.
        /// </summary>
        /// <param name="resolveResult" type="">Required. The value returned with the completed promise.</param>
        /// <returns type=""></returns>

        return new Promise(
            function (resolve, reject) {
                resolve(resolveResult);
            });
    };

    //#endregion static methods
}
///#source 1 1 /scripts/subtle/syncWorker.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

// This worker is used when webworkers aren't available.
// It will function synchronously but use the same
//   mechanisms that the asynchronous webworkers use.
function syncWorker() {
    var result;

    // PostMessage is how you interact with a worker. You post some data to the worker
    // and it will process it and return it's data to the onmessage function.
    // Since we're really running synchronously, we call the crypto function in
    // PostMessage and wait for the result. Then we call the OnMessage fuction with
    // that result. This will give the same behavior as a web-worker.
    function postMessage(data) {

        // Web-workers will automatically return an error message when an 
        // error is thrown within the web worker.
        // When using a sync worker, we'll have to catch thrown errors, so we
        // need a try/catch block here.
        try {
            result = msrcryptoWorker.jsCryptoRunner(/*@static_cast(typeEvent)*/{ data: data });
        } catch (ex) {
            this.onerror({ data: ex.message, type: "error" });
            return;
        }

        // 'process' operations don't return values, so we don't
        // forward the worker return message.
        if (!data.operationSubType || data.operationSubType !== "process") {
            this.onmessage({ data: result });
        }

    }

    return {
        postMessage: postMessage,
        onmessage: null,
        onerror: null,
        terminate: function () {
            // This is a no-op to be compatible with webworker.
        }
    };
}
///#source 1 1 /scripts/subtle/operations.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

/// <dictionary>Obj,oncomplete,onerror</dictionary>

function baseOperation(processResults) {

    var result = null,
        oncompleteCallback = null,
        onerrorCallback = null,
        retObj,
        promise,
        resolveFunc,
        rejectFunc;

    // Create a new promise
    promise = new Promise(
        function (resolve, reject) {
            resolveFunc = resolve;
            rejectFunc = reject;
        });


    // Called when the worker returns a result
    function opDispatchEvent(/*@type(Event)*/e) {

        // If the event is an Error call the onError callback
        if (e.type === "error") {

            // If the onerror callback has been set, call it.
            // If the onerror callback has been set, call it.
            if (rejectFunc) {
                rejectFunc.apply(promise, [e.message ? e.message : e]);
            }
            return;
        }

        // Otherwise call the oncomplete callback
        this.result = processResults(e.data);

        // Resolve the promise with the result 
        resolveFunc.apply(promise, [this.result]);
        
        return;
    }

    retObj = {
        dispatchEvent: opDispatchEvent,
        promise : promise,
        result: null
    };

    return retObj;
}

function keyOperation() {

    function processResult(result) {

        // Could be the result of an import, export, generate.
        // Get the keyData and keyHandle out.
        switch (result.type) {

            // KeyImport: save the new key
            case "keyGeneration":
            case "keyImport":
            case "keyDerive":
                keys.add(result.keyHandle, result.keyData);

                return result.keyHandle;

                // KeyExport: return the export data
            case "keyExport":
                return result.keyHandle;

            case "keyPairGeneration":
                keys.add(result.keyPair.publicKey.keyHandle, result.keyPair.publicKey.keyData);
                keys.add(result.keyPair.privateKey.keyHandle, result.keyPair.privateKey.keyData);
                return {
                    publicKey: result.keyPair.publicKey.keyHandle,
                    privateKey: result.keyPair.privateKey.keyHandle
                };

            default:
                throw new Error("Unknown key operation");
        }

        return;
    }

    return baseOperation(processResult);
}

function cryptoOperation(cryptoContext) {

    function processResult(result) {

        // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
        result = toArrayBufferIfSupported(result);

        // A normal array will be returned.
        return result;
    }

    var op = baseOperation(processResult);

    op.process = function (buffer) {
        cryptoContext.operationSubType = "process";
        cryptoContext.buffer = utils.toArray(buffer);
        workerManager.continueJob(this,
            utils.clone(cryptoContext));
    };

    op.finish = function () {
        cryptoContext.operationSubType = "finish";
        cryptoContext.buffer = [];
        workerManager.continueJob(this,
            utils.clone(cryptoContext));
    };

    op.abort = function () {
        workerManager.abortJob(this);
    };

    op.onabort = null;
    op.onprogress = null;

    op.algorithm = cryptoContext.algorithm || null;
    op.key = cryptoContext.keyHandle || null;

    return op;
}

function toArrayBufferIfSupported(dataArray) {

    // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
    if (typedArraySupport && dataArray.pop) {

        // We can't write to an ArrayBuffer directly so we create a Uint8Array
        //   and return it's buffer property.
        return (new Uint8Array(dataArray)).buffer;
    }

    // Do nothing and just return the passed-in array.
    return dataArray;
}

///#source 1 1 /scripts/subtle/keyManager.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

// Storage for the keyData.
// Stored as {keyHandle: keyHandle, keyData: keyData} objects.
var keys = [];
keys.add = function (keyHandle, keyData) {
    keys.push({ keyHandle: keyHandle, keyData: keyData });
};
keys.remove = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            keys = keys.splice(i, 1);
            return;
        }
    }
};
keys.lookup = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            return keys[i].keyData;
        }
    }
    return null;
};
///#source 1 1 /scripts/subtle/workerManager.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

// Manages the pool of webworkers and job queue.
// We first try to find an idle webworker and pass it a crypto job.
// If there are no workers or they are all busy, we'll create a new one.
// If we're at our (somewhat arbitrary) limit for workers we'll queue the 
//   job until a worker is free.
// When a worker finishes and the queue is empty it will kill itself to
//   free resources.
// However, we will keep a couple idle workers alive for future use.
// In the case webworkers are not supported <IE10 we will run in synchronous
//   mode. Jobs will be executed synchronously as they arrive using a single
//   syncWorker (pretend webworker that just runs synchronously in this same script).
var workerManager = (function () {

    // The max number of webworkers we'll spawn.
    var maxWorkers = 12;

    // The number of idle webworkers we'll allow to live for future use.
    var maxFreeWorkers = 2;

    // Storage for webworker.
    var workerPool = [];

    // Queue for jobs when all workers are busy.
    var jobQueue = [];

    // Each job gets and id.
    var jobId = 0;

    function getFreeWorker() {

        purgeWorkerType(!asyncMode);

        // Get the first non-busy worker
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                return workerPool[i];
            }
        }

        return null;
    }

    function purgeWorkerType(webWorker) {
        for (var i = workerPool.length - 1; i >= 0; i -= 1) {
            if (workerPool[i].isWebWorker === webWorker) {
                workerPool[i].terminate();
                workerPool.splice(i, 1);
            }
        }
    }

    function freeWorkerCount() {
        var freeWorkers = 0;
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                freeWorkers += 1;
            }
        }
        return freeWorkers;
    }

    function addWorkerToPool(worker) {
        workerPool.push(worker);
    }

    function removeWorkerFromPool(worker) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i] === worker) {
                // Kill the webworker.
                worker.terminate();
                // Remove the worker object from the pool.
                workerPool.splice(i, 1);
                return;
            }
        }
    }

    function lookupWorkerByOperation(operation) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i].operation === operation) {
                return workerPool[i];
            }
        }
        // Didn't find the worker!?
        return null;
    }

    function queueJob(operation, data) {
        jobQueue.push({ operation: operation, data: data, id: jobId++ });
    }

    function jobCompleted(worker) {

        worker.busy = false;
        worker.operation = null;

        // Check the queue for waiting jobs if in async mode
        if (asyncMode) {
            if (jobQueue.length > 0) {
                var job = jobQueue.shift();
                continueJob(job.operation, job.data);

            } else if (freeWorkerCount() > maxFreeWorkers) {
                removeWorkerFromPool(worker);
            }
        }

    }

    function createNewWorker(operation) {

        // Use a web worker if supported
        //   else use a synchronous worker.
        var worker;

        if (asyncMode) {
            try {
                worker = new Worker(scriptUrl);
                worker.postMessage({ prngSeed: msrcryptoPseudoRandom.getBytes(48) });
                worker.isWebWorker = true;
            } catch (ex) {
                asyncMode = false;
                publicMethods.forceSync = true;
                worker = syncWorker();
                worker.isWebWorker = false;
            }

        } else {
            worker = syncWorker();
            worker.isWebWorker = false;
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        worker.busy = false;

        // The worker will call this function when it completes its job.
        worker.onmessage = function (/*@type(typeEvent)*/ e) {

            var op = worker.operation;

            // Check if there are queued jobs for this operation
            for (var i = 0; i < jobQueue.length; i++) {
                if (jobQueue[i].operation === worker.operation) {
                    var job = jobQueue[i];
                    jobQueue.splice(i, 1);
                    postMessageToWorker(worker, job.data);
                    return;
                }
            }

            // Send the results to the operation object and it will fire
            //   it's onCompleted event.
            if (op && e.data.type !== "process") {
                jobCompleted(worker);
                op.dispatchEvent(e);
            }
        };

        // If an error occurs within the worker.
        worker.onerror = function (/*@type(typeEvent)*/ e) {

            var op = worker.operation;

            jobCompleted(worker);

            // Send the error to the operation object and it will fire
            //   it's onError event.
            op.dispatchEvent(e);

        };

        // Add this new worker to the worker pool.
        addWorkerToPool(worker);

        return worker;
    }

    function abortJob(cryptoOperationObject) {
        var worker = lookupWorkerByOperation(cryptoOperationObject);
        if (worker) {
            removeWorkerFromPool(worker);
        }
    }

    // Creates or reuses a worker and starts it up on work.
    function runJob(/*@dynamic*/ operation, data) {

        var worker = null;

        // If the caller adds the "forceSync" property and sets it to true.
        // Then run in synchronous mode even if webworkers are available.
        // This can be turned on or off on the fly.
        asyncMode = webWorkerSupport && !(publicMethods.forceSync);


        // Get the first idle worker.
        worker = getFreeWorker();

        // Queue this job if all workers are busy and we're at our max instances
        if (asyncMode && worker === null && workerPool.length >= maxWorkers) {
            queueJob(operation, data);
            return;
        }

        // No idle workers, we'll have to create a new one.
        if (worker === null) {
            worker = createNewWorker(operation);
        }

        if (worker === null) {
            queueJob(operation, data);
            throw new Error("could not create new worker");
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        // Mark this worker as 'busy'. It's about to run a job.
        worker.busy = true;

        // Start the worker
        postMessageToWorker(worker, data);

    }

    function continueJob(/*type(cryptoOperation)*/operation, data) {

        // Lookup the worker that is handling this operation
        var worker = lookupWorkerByOperation(operation);

        if (worker) {
            postMessageToWorker(worker, data);
            return;
        }

        // If we didn't find a worker, this is probably the first
        //  'process' message so we need to start a new worker.
        runJob(operation, data);

    }

    function postMessageToWorker(worker, data) {
        // Start the worker now if using webWorkers
        //   else, defer running until later.
        if (asyncMode) {
            worker.data = data;
            worker.postMessage(data);
        } else {

            var func = (function (postData) {

                return function () {
                    return worker.postMessage(postData);
                }

            })(data);

            var id = setTimeout(func, 0);
        }

        return;
    }

    return {
        runJob: runJob,
        continueJob: continueJob,
        abortJob: abortJob
    };

})();
///#source 1 1 /scripts/subtle/subtleInterface.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

var utils = msrcryptoUtilities;

function checkOperation(operationType, algorithmName) {
    if (!operations.exists(operationType, algorithmName)) {
        throw new Error("unsupported algorithm");
    }
}

// The list of possible parameters passed to the subtle interface.
var subtleParameters = [
   /* 0 */ { name: "algorithm", type: "Object", required: true },
   /* 1 */ { name: "keyHandle", type: "Object", required: true },
   /* 2 */ { name: "buffer", type: "Array", required: false },
   /* 3 */ { name: "signature", type: "Array", required: true },
   /* 4 */ { name: "format", type: "String", required: true },
   /* 5 */ { name: "keyData", type: "Object", required: true },
   /* 6 */ { name: "extractable", type: "Boolean", required: false },
   /* 7 */ { name: "keyUsage", type: "Array", required: false },
   /* 8 */ { name: "derivedKeyType", type: "Object", required: true },
   /* 9 */ { name: "length", type: "Number", required: false },

   /* 10 */ { name: "extractable", type: "Boolean", required: true },
   /* 11 */ { name: "keyUsage", type: "Array", required: true }
];

// The set of expected parameters passed to each subtle function.
var subtleParametersSets = {
    encrypt: [0, 1, 2],
    decrypt: [0, 1, 2],
    sign: [0, 1, 2],
    verify: [0, 1, 3, 2],
    digest: [0, 2],
    generateKey: [0, 6, 7],
    importKey: [4, 5, 0, 10, 11],
    exportKey: [0, 4, 1, 6, 7],
    deriveKey: [0, 1, 8, 6, 7],
    deriveBits: [0, 1, 9],
    wrapKey: [1, 1, 0],
    unwrapKey: [2, 0, 1, 6, 7]
};

// Looks up the stored key data for a given keyHandle
function lookupKeyData(handle) {
    var data = keys.lookup(handle);

    if (!data) {
        throw new Error("key not found");
    }

    return data;
}

// This function processes each parameter passed by the user. Each parameter
// is compared against an expected parameter. It should be of the expected type.
// Typed-Array parameters are converted to regular Arrays.
function buildParameterCollection(operationName, parameterSet) {

    var parameterCollection = { operationType: operationName },
        operationParameterSet = subtleParametersSets[operationName];

    for (var i = 0; i < operationParameterSet.length; i += 1) {

        var expectedParam = subtleParameters[operationParameterSet[i]];
        var actualParam = parameterSet[i];

        // Verify the required parameters are present.
        if (!actualParam) {
            if (expectedParam.required) {
                throw new Error(expectedParam.name);
            } else {
                continue;
            }
        }

        // If this parameter is a typed-array convert it to a regular array.
        if (actualParam.subarray) {
            actualParam = utils.toArray(actualParam);
        }

        // If this parameter is an ArrayBuffer convert it to a regular array.
        if (utils.getObjectType(actualParam) == "ArrayBuffer") {
            actualParam = utils.toArray(actualParam);
        }

        // Verify the actual parameter is of the expected type.
        if (msrcryptoUtilities.getObjectType(actualParam) !== expectedParam.type) {
            throw new Error(expectedParam.name);
        }

        // If this parameter is an algorithm object convert it's name to lowercase.
        if (expectedParam.name === "algorithm") {

            actualParam.name = actualParam.name.toLowerCase();

            // If the algorithm has a typed-array IV, convert it to a regular array.
            if (actualParam.iv) {
                actualParam.iv = utils.toArray(actualParam.iv);
            }

            // If the algorithm has a typed-array Salt, convert it to a regular array.
            if (actualParam.salt) {
                actualParam.salt = utils.toArray(actualParam.salt);
            }

            // If the algorithm has a typed-array AdditionalData, convert it to a regular array.
            if (actualParam.additionalData) {
                actualParam.additionalData = utils.toArray(actualParam.additionalData);
            }

            // If this algorithm has a hash property in the form 'hash: hashName'
            // Convert it to hash: {name: hashName} as per the W3C spec.
            if (actualParam.hash && !actualParam.hash.name && msrcryptoUtilities.getObjectType(actualParam.hash) === "String") {
                actualParam.hash = { name: actualParam.hash };
            }
        }

        // KeyWrap has two keyHandle paramters. We add '1' to the second param name
        // to avoid a duplicate name.
        if (parameterCollection.hasOwnProperty(expectedParam.name)) {
            parameterCollection[expectedParam.name + "1"] = actualParam;
        } else {
            parameterCollection[expectedParam.name] = actualParam;
        }
    }

    return parameterCollection;
}

function executeOperation(operationName, parameterSet, keyFunc) {

    var pc = buildParameterCollection(operationName, parameterSet);

    // Verify this type of operation is supported by this library (encrypt, digest, etc...)
    checkOperation(operationName, pc.algorithm.name);

    // Add the key data to the parameter object
    if (pc.keyHandle) {
        pc.keyData = lookupKeyData(pc.keyHandle);
    }

    // Add the key data to the parameter object
    // KeyWrap has two keyHandle parameters - this handles the second key.
    if (pc.keyHandle1) {
        pc.keyData1 = lookupKeyData(pc.keyHandle1);
    }

    // ECDH.DeriveBits passes a public key in the algorithm
    if (pc.algorithm && pc.algorithm.public) {
        pc.additionalKeyData = lookupKeyData(pc.algorithm.public);
    }

    var op = keyFunc ? keyOperation(pc) : cryptoOperation(pc);

    // Run the crypto now if a buffer is supplied
    //   else wait until process() and finish() are called.
    if (keyFunc || pc.buffer || operationName === "deriveBits" || operationName === "wrapKey") {
        workerManager.runJob(op, pc);
    }

    return op.promise;
}

var publicMethods = {

    encrypt: function (algorithm, keyHandle, buffer) {
        /// <signature>
        /// <summary>Encrypt a UInt8Array of data. Encrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="ArrayBuffer" />
        /// </signature>
        /// <signature>
        /// <summary>Encrypt an array of bytes. Encrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes (number from 0-255)</param>
        ///     <returns type="Array" />
        /// </signature>
        /// <signature>
        /// <summary>Encrypt an array of bytes. Encrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">A continuous array of bytes (number values from 0-255)</param>
        ///     <returns type="ArrayBuffer" />
        /// </signature>

        return executeOperation("encrypt", arguments, 0);
    },

    decrypt: function (algorithm, keyHandle, buffer) {
        /// <signature>
        ///     <summary>Decrypt a UInt8Array of data. 
        ///     Decrypt will return an ArrayBuffer if supported, otherwise it will return an Array of byte values (numbers from 0-255)</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Decrypt an array of byte values. Decrypt will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("decrypt", arguments, 0);
    },

    sign: function (algorithm, keyHandle, buffer) {
        /// <signature>
        ///     <summary>Sign a UInt8Array of data. 
        ///     Sign will return a signature as an ArrayBuffer if supported, otherwise it will return an Array of byte values (numbers from 0-255)</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Sign an array of byte values. Sign will return an ArrayBuffer if supported, otherwise it will return a regular Array.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("sign", arguments, 0);
    },

    verify: function (algorithm, keyHandle, signature, buffer) {
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="UInt8Array">UInt8Array</param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="UInt8Array">UInt8Array</param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Verify a signature.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="signature" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("verify", arguments, 0);
    },

    digest: function (algorithm, buffer) {
        /// <signature>
        ///     <summary>Digest data using a specified cryptographic hash algorithm</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="buffer" type="UInt8Array" optional="true">UInt8Array</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Digest data using a specified cryptographic hash algorithm</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="buffer" type="Array" optional="true">An array of bytes values (numbers from 0-255)</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>
        return executeOperation("digest", arguments, 0);
    },

    generateKey: function (algorithm, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Generate a new key for use with the algorithm specified by the algorithm parameter</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        return executeOperation("generateKey", arguments, 1);
    },

    deriveKey: function (algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Generate a key for the specified derivedKeyType, using the specified cryptographic key derivation algorithm with the given baseKey as input.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="baseKey" type="Key"></param>
        ///     <param name="deriveKeyType" type="Algorithm"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        return executeOperation("deriveKey", arguments, 1);
    },

    deriveBits: function (algorithm, baseKey, length) {
        /// <signature>
        ///     <summary>Generate an array of bytes from a given baseKey as input.</summary>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="baseKey" type="Key"></param>
        ///     <param name="length" type="Number">Number of bytes to return.</param>
        ///     <returns type="CryptoOperation" />
        /// </signature>

        return executeOperation("deriveBits", arguments, 0);
    },

    importKey: function (format, keyData, algorithm, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Constructs a new Key object using the key data specified by the keyData parameter.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="keyData" type="Object">An object representing a key in jwk format.</param>
        ///     <param name="algorithm" type="Algorithm"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>


        return executeOperation("importKey", arguments, 1);
    },

    exportKey: function (format, keyHandle) {
        /// <signature>
        ///     <summary>Exports the given key material of the Key object as specified by the key parameter.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="key" type="Key"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        // Export is one of the few calls where the caller does not supply an algorithm 
        // since it's already a property of the key to be exported.
        // So, we're pulling it out of the key and adding it to the parameter set since
        // it is used as a switch to route the parameters to the right function.
        // Now we don't have to treat this as a special case in the underlying code.
        return executeOperation("exportKey", [keyHandle.algorithm, format, keyHandle], 1);
    },

    wrapKey: function (format, key, wrappingKey, wrappingKeyAlgorithm) {
        /// <signature>
        ///     <summary>Returns a KeyOperation object which will asynchronously return an array containing the key material of key, encrypted with keyEncryptionKey using the specified keyWrappingAlgorithm.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="key" type="Key"></param>
        ///     <param name="wrappingKey" type="Key"></param>
        ///     <param name="wrappingKeyAlgorithm" type="Algorithm"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        return executeOperation("wrapKey", arguments, 0);
    },

    unwrapKey: function (format, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsage) {
        /// <signature>
        ///     <summary>Construct a Key object from encrypted key material.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="unwrappingKey" type="Array">An array of bytes values (numbers from 0-255)</param>
        ///     <param name="unwrapAlgorithm" type="Algorithm"></param>
        ///     <param name="keyEncryptionKey" type="Key"></param>
        ///     <param name="extractableunwrappedKeyAlgorithm type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>
        /// <signature>
        ///     <summary>Construct a Key object from encrypted key material.</summary>
        ///     <param name="format" type="String"></param>
        ///     <param name="unwrappingKey" type="UInt8Array"></param>
        ///     <param name="unwrapAlgorithm" type="Algorithm"></param>
        ///     <param name="unwrappedKeyAlgorithm" type="Key"></param>
        ///     <param name="extractable" type="Boolean" optional="true"></param>
        ///     <param name="keyUsage" type="Array" optional="true"></param>
        ///     <returns type="KeyOperation" />
        /// </signature>

        return executeOperation("unwrapKey", arguments, 1);
    }

};
///#source 1 1 /scripts/subtle/tail.js
//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
//    
//    LICENSED UNDER THE APACHE LICENSE, VERSION 2.0 (THE "LICENSE");
//    YOU MAY NOT USE THIS FILE EXCEPT IN COMPLIANCE WITH THE LICENSE.
//    YOU MAY OBTAIN A COPY OF THE LICENSE AT
//    
//    http://www.apache.org/licenses/LICENSE-2.0
//    
//    UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING, SOFTWARE
//    DISTRIBUTED UNDER THE LICENSE IS DISTRIBUTED ON AN "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
//    SEE THE LICENSE FOR THE SPECIFIC LANGUAGE GOVERNING PERMISSIONS AND
//    LIMITATIONS UNDER THE LICENSE.
//
//*******************************************************************************

return publicMethods;

})();

}

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

var publicMethods = {

    /// <field type = 'Object' static="false">Microsoft Research Javascript Crypto Library Subtle interface.</field>
    subtle: msrcryptoSubtle,

    getRandomValues: function(array) {
        /// <signature>
        ///     <summary>Places cryptographically random values into the given array.</summary>
        ///     <param name="array" type="Array"></param>
        ///     <returns type="Array" />
        /// </signature>
        /// <signature>
        ///     <summary>Places cryptographically random values into the given array.</summary>
        ///     <param name="array" type="ArrayBufferView"></param>
        ///     <returns type="ArrayBufferView">Returns ArrayBufferView if supported.</returns>
        /// </signature>

        var i;
        var randomValues = msrcryptoPseudoRandom.getBytes(array.length);
        for (i = 0; i < array.length; i+=1) {
            array[i] = randomValues[i];
        }
        return array;
    },

    initPrng: function (entropyData) {
        /// <signature>
        ///     <summary>Add entropy to the PRNG.</summary>
        ///     <param name="entropyData" type="Array">Entropy input to seed or reseed the PRNG.</param>
        /// </signature>
        
        var entropyDataType = Object.prototype.toString.call(entropyData);

        if (entropyDataType !== "[object Array]" && entropyDataType !== "[object Uint8Array]") {
            throw new Error("entropyData must be a Array or Uint8Array");
        }

        // Mix the user-provided entropy into the entropy pool - only in the main thread.
        entropyPool && entropyPool.reseed(entropyData);

        // Reseed the PRNG that was initialized below
        msrcryptoPseudoRandom.reseed(entropyPool.read(48));
        fprngEntropyProvided = true;
    },

    toBase64: function (data, toBase64Url) {
        /// <signature>
        ///     <summary>Convert string or array data to Base64.</summary>
        ///     <param name="data" type="Array">Byte values (numbers 0-255)</param>
        ///     <param name="toBase64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different from Base64 encoding.)</param>
        ///     <returns type="Array" />
        /// </signature>
        /// <signature>
        ///     <summary>Convert string or array data to Base64.</summary>
        ///     <param name="data" type="String"></param>
        ///     <param name="toBase64Url" type="Boolean" optional="true">Return Base64Url encoding (this is different from Base64 encoding.)</param>
        ///     <returns type="Array" />
        /// </signature>

        return  msrcryptoUtilities.toBase64(data, false);
    },

    base64ToString: function (base64String) {
        /// <signature>
        ///     <summary>Decode a Base64 encoded string to a plain string.</summary>
        ///     <param name="base64String" type="String">Base64 encoded string.</param>
        ///     <returns type="String" />
        /// </signature>
        return msrcryptoUtilities.base64ToString(base64String);
    },

    /// <field type = 'String'>URL of the this msrCrypto script.</field>
    url : scriptUrl

};

// Expose the math library if present
if (typeof cryptoMath !== "undefined") { 
    publicMethods.cryptoMath = cryptoMath; 
}

if (typeof testInterface !== "undefined") {
    publicMethods.testInterface = testInterface;
}

// Initialize the main entropy pool instance on the main thread, only.
// I want only the main thread to create and manage the central entropy pool.
// All workers would have their own PRNG instance initialized by injected entropy from the main thread.
var entropyPool;
if (!runningInWorkerInstance) {
    entropyPool = entropyPool || new MsrcryptoEntropy();

    // Initialize the entropy pool in the main thread.
    // There is only one entropy pool.
    entropyPool.init();
    var localEntropy = entropyPool.read(48);            // 48 is from SP800-90A; could be longer
    msrcryptoPseudoRandom.init(localEntropy);
}

return publicMethods;

})();