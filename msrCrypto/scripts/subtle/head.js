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