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