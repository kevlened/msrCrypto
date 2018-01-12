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