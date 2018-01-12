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

/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.15.0.js" />
/// <reference path="testVectors/tv_aes.js" />

var promiseTest = {

    executorSync: function (result) {
        return function (resolve, reject) {
            resolve(result);
        }
    },

    executorAsync: function (result, duration) {
        return function (resolve, reject) {
            setTimeout(function () { resolve(result); }, duration);
        }
    },

    executorFailSync: function (reason) {
        return function (resolve, reject) {
            reject(reason);
        }
    },

    executorFailAsync: function (reason, duration) {
        return function (resolve, reject) {
            setTimeout(function () { reject(reason); }, duration);
        }
    }
};


module("Promises");

asyncTest("Promise.then synchronous function", function () {

    var promise = new Promise(promiseTest.executorSync(4));

    promise.then(function (result) {
        start();
        equal(result, 4);
    });

});

asyncTest("Promise.then async function", function () {

    var promise = new Promise(promiseTest.executorAsync(4, 200));

    promise.then(function (result) {
        start();
        equal(result, 4);
    });

});

asyncTest("Promise.then no result", function () {

    var ud;

    var promise = new Promise(promiseTest.executorAsync(ud, 200));

    promise.then(function (result) {
        start();
        ok(true);
    });

});

asyncTest("Promise.then chaining sync", function () {

    var promise = new Promise(promiseTest.executorSync(4))
    .then(function (result) { return result + 1; })
    .then(function (result) { return result + 1; })
    .then(function (result) { return result + 1; })
    .then(function (result) {
        start();
        equal(result, 7);
    })

});

asyncTest("Promise.then chaining async promises", function () {

    var executor = function (resolve, reject) {
        setTimeout(function () { resolve(4); }, 200);
    };

    var promise = new Promise(executor)
    .then(function (result) { return new Promise(executor); })
    .then(function (result) { return new Promise(executor); })
    .then(function (result) { return new Promise(executor); })
    .then(function (result) {
        start();
        equal(result, 4);
    })

});

asyncTest("Promise.then chaining sync promises", function () {

    var promise = new Promise(promiseTest.executorSync(4))
    .then(function (result) { return new Promise(promiseTest.executorSync(++result)); })
    .then(function (result) { return new Promise(promiseTest.executorSync(++result)); })
    .then(function (result) { return new Promise(promiseTest.executorSync(++result)); })
    .then(function (result) {
        start();
        equal(result, 7);
    })

});

asyncTest("Promise.then multiple then sync", function () {

    var promise = new Promise(promiseTest.executorSync(4));

    var thenCount = 0;

    promise.then(function (result) {
        ++thenCount;
        return;
    });

    promise.then(function (result) {
        if (++thenCount == 2) {
            start();
            ok(true);
        }
        return;
    });


});

asyncTest("Promise.then x 2", function () {

    var thenCount = 0;

    var promise = new Promise(promiseTest.executorAsync(4, 200));

    function thenFunc(result) {
        if (++thenCount == 2) {
            start();
            ok(true);
        }
        return;
    }

    promise.then(thenFunc);

    promise.then(thenFunc);

});

asyncTest("Promise.then x 2 - with chaining", function () {
    /// <summary>
    /// A single promise with then() being called twice.
    /// ThenA returns another promise.
    /// ThenB returns a value.
    /// Verify both Thens and chains are resolved.
    /// </summary>

    var promise = new Promise(promiseTest.executorAsync(5, 200));

    var total = 0;

    promise.then( //Then A
        function (result) {
            return new Promise(promiseTest.executorAsync(6 + result, 200));
        })
    .then(
        function (result) {
            start();
            total += result;
            // Each then gets 5 from the first promise.  ThenA adds 6 while ThenB adds 7
            // to the total for 23.
            equal(total, (5 + 6) + (5 + 7));
        });

    promise.then( //Then B
        function (result) {
            return 7 + result;
        })
    .then(
        function (result) {
            total += result;
        });
});

asyncTest("Promise.all async", function () {

    eval(4);

    var p1 = new Promise(promiseTest.executorAsync(1, 300));
    var p2 = new Promise(promiseTest.executorAsync(2, 100));
    var p3 = new Promise(promiseTest.executorAsync(3, 400));

    Promise.all([p3, p1, p2]).then(
        function (results) {
            start();
            equal(results.length, 3);
            equal(results[0], 3);
            equal(results[1], 1);
            equal(results[2], 2);
        });

});

asyncTest("Promise.all sync", function () {

    eval(4);

    var p1 = new Promise(promiseTest.executorSync(1));
    var p2 = new Promise(promiseTest.executorSync(2));
    var p3 = new Promise(promiseTest.executorSync(3));

    Promise.all([p2, p3, p1]).then(
        function (results) {
            start();
            equal(results.length, 3);
            equal(results[0], 2);
            equal(results[1], 3);
            equal(results[2], 1);
        });

});

asyncTest("Promise.race sync", function () {

    eval(4);

    var p1 = new Promise(promiseTest.executorSync(1));
    var p2 = new Promise(promiseTest.executorSync(2));
    var p3 = new Promise(promiseTest.executorSync(3));

    Promise.race([p2, p3, p1]).then(
        function (result) {
            start();
            equal(result, 2);
        });

});

asyncTest("Promise.race async", function () {

    eval(4);

    var p1 = new Promise(promiseTest.executorAsync(1, 300));
    var p2 = new Promise(promiseTest.executorAsync(2, 200));
    var p3 = new Promise(promiseTest.executorAsync(3, 100));

    Promise.race([p2, p3, p1]).then(
        function (result) {
            start();
            equal(result, 3);
        });

});

asyncTest("Promise.resolve", function () {

    Promise.resolve(4).then(
        function (result) {
            start();
            equal(result, 4);
        });

});

/// ===== reject ====================================================

asyncTest("Promise.catch synchronous function", function () {

    var promise = new Promise(promiseTest.executorFailSync(4));

    promise["catch"](function (reason) {
        start();
        equal(reason, 4);
    });

});

asyncTest("Promise.catch async function", function () {

    var promise = new Promise(promiseTest.executorFailAsync(4, 200));

    promise["catch"](function (reason) {
        start();
        equal(reason, 4);
    });

});

asyncTest("Promise.catch no reason", function () {

    var ud;

    var promise = new Promise(promiseTest.executorFailAsync(ud, 200));

    promise["catch"](function (reason) {
        start();
        ok(true);
    });

});

asyncTest("Promise.catch chaining sync", function () {

    var promise = new Promise(promiseTest.executorFailSync(4))
    ["catch"](function (reason) { return reason + 1; })
    .then(function (reason) {
        start();
        equal(reason, 5);
    });

});

asyncTest("Promise.catch chaining async promises", function () {

    var promise = new Promise(promiseTest.executorFailAsync(4, 200))
    ["catch"](
        function (reason) {
            return new Promise(promiseTest.executorFailAsync(5, 200));
        })
    ["catch"](
        function (reason) {
            return new Promise(promiseTest.executorFailAsync(6, 200));
        })
    ["catch"](
        function (reason) {
            return new Promise(promiseTest.executorFailAsync(7, 200));
        })
    ["catch"](
        function (reason) {
            start();
            equal(reason, 7);
        })

});

asyncTest("Promise.catch chaining sync promises", function () {

    var promise = new Promise(promiseTest.executorFailSync(4))
    ["catch"](function (reason) { return new Promise(promiseTest.executorFailSync(++reason)); })
    ["catch"](function (reason) { return new Promise(promiseTest.executorFailSync(++reason)); })
    ["catch"](function (reason) { return new Promise(promiseTest.executorFailSync(++reason)); })
    ["catch"](function (reason) {
        start();
        equal(reason, 7);
    })

});

asyncTest("Promise.catch multiple then sync", function () {

    var promise = new Promise(promiseTest.executorFailSync(4));

    var catchCount = 0;

    promise["catch"](function (reason) {
        ++catchCount;
        return;
    });

    promise["catch"](function (reason) {
        if (++catchCount == 2) {
            start();
            ok(true);
        }
        return;
    });


});

asyncTest("Promise.catch x 2", function () {

    var catchCount = 0;

    var promise = new Promise(promiseTest.executorFailAsync(4, 200));

    function catchFunc(reason) {
        if (++catchCount == 2) {
            start();
            ok(true);
        }
        return;
    }

    promise["catch"](catchFunc);

    promise["catch"](catchFunc);

});

asyncTest("Promise.catch x 2 - with chaining", function () {
    /// <summary>
    /// A single promise with then() being called twice.
    /// ThenA returns another promise.
    /// ThenB returns a value.
    /// Verify both Thens and chains are resolved.
    /// </summary>

    var promise = new Promise(promiseTest.executorFailAsync(5, 100));

    var total = 0;

    promise["catch"]( //Then A
        function (reason) {
            return new Promise(promiseTest.executorFailAsync(6 + reason, 400));
        })
    ["catch"](
        function (reason) {
            start();
            total += reason;
            // Each then gets 5 from the first promise.  ThenA adds 6 while ThenB adds 7
            // to the total for 23.
            equal(total, (5 + 6) + (5 + 7));
        });

    promise["catch"]( //Then B
        function (reason) {
            return 7 + reason;
        })
    .then(
        function (reason) {
            total += reason;
        });
});

asyncTest("Promise.all fail async", function () {

    var p1 = new Promise(promiseTest.executorAsync(1, 300));
    var p2 = new Promise(promiseTest.executorAsync(2, 100));
    var p3 = new Promise(promiseTest.executorFailAsync(3, 400));

    Promise.all([p3, p1, p2])["catch"](
        function (reason) {
            start();
            equal(reason, 3);
        });

});

asyncTest("Promise.all fail sync", function () {

    var p1 = new Promise(promiseTest.executorSync(1));
    var p2 = new Promise(promiseTest.executorFailSync(2));
    var p3 = new Promise(promiseTest.executorSync(3));

    Promise.all([p3, p1, p2])["catch"](
        function (reason) {
            start();
            equal(reason, 2);
        });

});

asyncTest("Promise.race fail sync", function () {

    var p1 = new Promise(promiseTest.executorSync(1));
    var p2 = new Promise(promiseTest.executorFailSync(2));
    var p3 = new Promise(promiseTest.executorSync(3));

    Promise.race([p2, p3, p1])["catch"](
        function (reason) {
            start();
            equal(reason, 2);
        });

});

asyncTest("Promise.race fail async", function () {

    var p1 = Promise.reject(1);
    var p2 = new Promise(promiseTest.executorAsync(2, 200));
    var p3 = new Promise(promiseTest.executorFailAsync(3, 100));

    Promise.race([p2, p3, p1])["catch"](
        function (reason) {
            start();
            equal(reason, 1);
        });

});

asyncTest("Promise.reject", function () {

    Promise.reject(4)["catch"](
        function (reason) {
            start();
            equal(reason, 4);
        });

});