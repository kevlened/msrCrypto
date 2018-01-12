//*******************************************************************************
//
//    Copyright (c) 2014 Microsoft. All rights reserved.
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
