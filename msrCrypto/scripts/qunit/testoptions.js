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

QUnit.config.autostart = false;

function startTests() {
    button_startTests.value = "Stop";
    button_startTests.onclick = function () { stopTests() };

    QUnit.start();
}

function stopTests() {
    button_startTests.value = "Start Tests";
    button_startTests.onclick = function () { startTests() };

    QUnit.stop();
}

var setterSupport = (function () {
    try {
        Object.defineProperty({}, "oncomplete", {});
        return true;
    } catch (ex) {
        return false;
    }
}());

var webWorkerSupport = (typeof window.Worker !== "undefined");

var typedArraySupport = (typeof Uint8Array !== "undefined");

function forceSyncChange() {
    var check_forceSync = document.getElementById('check_forceSync');

    if (check_forceSync.checked) {
        msrCrypto.subtle.forceSync = true;
    } else {
        delete msrCrypto.subtle.forceSync;
    }
}

var buildTestControls = function () {

    var trt = document.getElementById("qunit-testrunner-toolbar");

    if (!trt) {
        setTimeout(
            function () {
                buildTestControls();
            }, 100);
        return;
    }

    var librariesPresent = [];

    for (var msrcryptoScript in cryptoLibraries) {
        librariesPresent.push(msrcryptoScript);
    }

    // Get the currently select library file (if present in the query string)
    var libraryParameter = getParameterByName("library");

    if (libraryParameter && cryptoLibraries[libraryParameter]) {
        window.msrCrypto = cryptoLibraries[libraryParameter];
    }

    var results = document.getElementById('qunit-testresult');
    if (results) {
        results.innerHTML = "Click button to start...<BR>&nbsp;";
    }

    var newDiv = trt.cloneNode(false);
    newDiv.id = "div_testOptions";
    //newDiv.class = '#qunit-testrunner-toolbar'

    var styleSheet = document.styleSheets[0];

    if (styleSheet.addRule) {
        styleSheet.addRule(".msrctable td", "font-family: Calibri, Helvetica, Arial, sans-serif;");
        styleSheet.addRule(".msrctable td", "font-size: smaller;");
        styleSheet.addRule(".msrctable td", "padding: 5px;");
    }
    //else {
    //    styleSheet.insertRule(".msrctable td", "font-family: Calibri, Helvetica, Arial, sans-serif;");
    //}

    var select_library = buildLibrarySelect(librariesPresent);

    var option = document.createElement("option");
    option.text = "MsCrypto";
    option.value = "MsCrypto";
    select_library.add(option);

    // Set the select to the selected library value
    select_library.value = libraryParameter || "msrcrypto.js";

    // If the a new library is selected, reload the page using the new library
    select_library.onchange = function (e) {

        if (select_library.value === "MsCrypto") {
            window._msrCrypto = window.msrCrypto;
            window.msrCrypto = window.msCrypto;
        } else {
            this.options[this.selectedIndex].value
            var selectedValue = select_library.options[select_library.selectedIndex].value;
            window.location.search = "?library=" + selectedValue;
            window.msrCrypto = cryptoLibraries[selectedValue];
            subtle = window.msrCrypto.subtle;
        }
    }

    newDiv.innerHTML = "<table class='msrctable' style='width: 100%; border-collapse: collapse;'><tr style='width: 100%; margin: 15px; background-color: #D2E0E6;'><td>" +
        "<input id='button_startTests' type='button' value='Start Tests' onclick='startTests();'></input>" +
        "</td>" +
        "<td width='70%'><input type='checkbox' id='check_forceSync' onClick='forceSyncChange();' " + (!webWorkerSupport ? "disabled" : "") + "></input>" +
        "<label title='forces the library to run synchronously even if web workers are available.' htmlFor='check_forceSync'>Force Synchronous</label>&nbsp;&nbsp;" +
        "<input type='checkbox' " + (webWorkerSupport ? "checked" : "") + " disabled></input>" +
        "<label title='Shows if web workers are available in this browser. Crypto operations will run asynchronously in web workers if available.'>Web Workers</label>&nbsp;&nbsp;" +
        "<input type='checkbox' " + (typedArraySupport ? "checked" : "") + " disabled></input>" +
        "<label>Typed Arrays</label>&nbsp;&nbsp;" +
        "<input type='checkbox' " + (setterSupport ? "checked" : "") + " disabled></input>" +
        "<label>Setter/Getters</label></td>" +
        "<td id='insert_select_here' align='right' style='padding-right: 0'><label>Library: </label>" +
        "</td>" +
        "</tr></table>";

    trt.parentElement.insertBefore(newDiv, trt);

    var td = document.getElementById('insert_select_here');

    td.appendChild(select_library);

    var m = window.msrCrypto;
}

function addEvent(elem, type, fn) {
    if (elem.addEventListener) {

        // Standards-based browsers
        elem.addEventListener(type, fn, false);
    } else if (elem.attachEvent) {

        // support: IE <9
        elem.attachEvent("on" + type, fn);
    } else {

        // Caller must ensure support for event listeners is present
        throw new Error("addEvent() was called in a context without event listener support");
    }
}

if (document) {
    addEvent(window, "load", buildTestControls);
}

function buildLibrarySelect(libraries) {

    var select = document.createElement('select');

    for (var i = 0; i < libraries.length; i++) {

        var option = document.createElement("option");
        option.text = libraries[i];
        option.value = libraries[i];

        select.add(option);
    }

    return select;
}

function getParameterByName(name) {
    var match = RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return match && decodeURIComponent(match[1].replace(/\+/g, ' '));
}