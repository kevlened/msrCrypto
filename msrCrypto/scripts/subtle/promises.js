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

// Add Promises if not supported
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