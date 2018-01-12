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