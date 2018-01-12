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