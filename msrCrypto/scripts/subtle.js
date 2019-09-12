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
            this.onerror({ data: ex.description, type: "error" });
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
        if (actualParam==null) {
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
