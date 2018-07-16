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