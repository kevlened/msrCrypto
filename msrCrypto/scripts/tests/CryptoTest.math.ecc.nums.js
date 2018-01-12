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

var eccTests = eccTests || {};

module("ECC-NUMS");

function bytesToHexString(bytes) {
    var result = "";

    for (var i = 0 ; i < bytes.length; i++) {

        var hexval = bytes[i].toString(16).toUpperCase();

        // add a leading zero if needed
        if (hexval.length == 1)
            hexval = "0" + hexval;

        result += ", 0x" + hexval;
    }

    return result;
}


test("ScalarMultiply NUMSP256T1", function () {

    // USE NIST CURVE FOR TESTING
    var curveTed = cryptoECC.createCurve("NUMSP256T1");
    var curveW = cryptoECC.createCurve("NUMSP256D1");

    var tedEcOperator = new cryptoECC.EllipticCurveOperatorFp(curveTed);
    var wEcOperator = new cryptoECC.EllipticCurveOperatorFp(curveW);

    // Get the generator as a point to double
    var tedPoint = curveTed.generator.clone();
    var wPoint = curveW.generator.clone();

    var tedOutputPoint = tedPoint.clone();
    var wOutputPoint = wPoint.clone();

    function getRandomBytes(length) {
        bytes = [];
        for (var i = 0; i < length; i++) {
            bytes.push(Math.floor(Math.random() * 256));
        }
        return bytes;
    }

    for (var i = 0; i < 10; i++) {

        // Create random scalar
        var k = getRandomBytes(curveTed.order.length * cryptoMath.DIGIT_NUM_BYTES);
        cryptoMath.reduce(cryptoMath.bytesToDigits(k), curveTed.order, k);

        wEcOperator.scalarMultiply(k, wPoint, wOutputPoint);
        tedEcOperator.scalarMultiply(k, tedPoint, tedOutputPoint);

    }

    ok(true);

});

test("PointDoubling NUMSP256D1", function () {

    // Get a Twisted Edwards 256 curve
    var curve = cryptoECC.createCurve("NUMSP256D1");

    // Get the generator as a point to double
    var point = curve.generator.clone();

    expectedValue = {
        x: cryptoMath.bytesToDigits([0x88, 0xC9, 0xA3, 0x81, 0xB1, 0xDA, 0x21, 0x41, 0xC6, 0xAB, 0xC3, 0x22, 0x59, 0x56, 0x93, 0xFB, 0x9C, 0xB6, 0x78, 0x45, 0x3B, 0x64, 0x60, 0x18, 0x59, 0x48, 0x63, 0x5D, 0x5F, 0x2B, 0x9E, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ].reverse()),
        y: cryptoMath.bytesToDigits([0x61, 0xDB, 0x82, 0x12, 0xA7, 0x1A, 0xF8, 0xE4, 0x10, 0x6C, 0x5D, 0x4B, 0xB4, 0x55, 0xDB, 0xCF, 0x3F, 0xD0, 0x9E, 0x3C, 0xF4, 0xCE, 0x23, 0x6E, 0x2E, 0x1C, 0x05, 0x15, 0xF2, 0x61, 0x5C, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ].reverse())
    }

    // Double the point
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    ecOperator.convertToMontgomeryForm(point);
    ecOperator.convertToJacobianForm(point);

    for (var i = 0; i < 10; i++) {
        ecOperator.double(point, point);
    }

    ecOperator.convertToAffineForm(point);
    ecOperator.convertToStandardForm(point);

    if (point.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (cryptoMath.compareDigits(point.x, expectedValue.x) !== 0) {
        ok(false, "point.x != expectedValue.x");
    }

    if (cryptoMath.compareDigits(point.y, expectedValue.y) !== 0) {
        ok(false, "point.y != expectedValue.y");
    }

    ok(true);
});

test("PointDoubling NUMSP256T1", function () {

    // Get a Twisted Edwards 256 curve
    var curve = cryptoECC.createCurve("NUMSP256T1");

    // Get the generator as a point to double
    var point = curve.generator.clone();

    expectedValue = {
        x: cryptoMath.bytesToDigits([0xC9, 0xB7, 0xCC, 0xB2, 0xC1, 0x6C, 0x6B, 0xEE, 0x42, 0xBD, 0xF2, 0x1F, 0x27, 0x2A, 0x84, 0x4E, 0x60, 0x17, 0xCE, 0x5A, 0x4F, 0x1B, 0x65, 0xF6, 0xA3, 0x3C, 0x00, 0x31, 0xA7, 0x37, 0x30, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].reverse()),
        y: cryptoMath.bytesToDigits([0xE7, 0x58, 0x3D, 0x54, 0xEA, 0x50, 0xC4, 0x4E, 0x9A, 0xEA, 0x41, 0xF8, 0x3A, 0x14, 0xA5, 0xF4, 0x50, 0xF4, 0xF8, 0xC5, 0x45, 0x80, 0x88, 0x98, 0x91, 0x5E, 0x16, 0x0B, 0xC5, 0x0F, 0x5C, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].reverse())
    }

    // Double the point
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    ecOperator.convertToExtendedProjective(point);

    for (var i = 0; i < 10; i++) {
        ecOperator.double(point, point);
    }

    ecOperator.normalize(point);

    if (point.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (cryptoMath.compareDigits(point.x, expectedValue.x) !== 0) {
        ok(false, "point.x != expectedValue.x");
    }

    if (cryptoMath.compareDigits(point.y, expectedValue.y) !== 0) {
        ok(false, "point.y != expectedValue.y");
    }

    ok(true);
});

test("PointConversionTedToWeierstrass", function () {

    var curve = cryptoECC.createCurve("NUMSP256T1");

    // Get the generator as a point to add
    var point = curve.generator.clone();

    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    var wPoint = new cryptoECC.EllipticCurvePointFp(
        cryptoECC.createCurve("NUMSP256D1"),
        false,
        cryptoMath.stringToDigits("0", 10),
        cryptoMath.stringToDigits("0", 10)
        );

    ecOperator.convertTedToWeierstrass(point, wPoint);

    ecOperator.convertWeierstrassToTed(wPoint, point);

    if (point.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (cryptoMath.compareDigits(point.x, curve.generator.x) !== 0) {
        ok(false, "point.x != curve.generator.x");
    }

    if (cryptoMath.compareDigits(point.y, curve.generator.y) !== 0) {
        ok(false, "point.y != curve.generator.y");
    }

    ok(true);
});

test("PointAddition NUMSP256T1", function () {

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createCurve("NUMSP256T1");

    // Get the generator as a point to add
    var point = curve.generator.clone();

    // expected value after 10 additions
    var expectedValue = {
        x: cryptoMath.bytesToDigits([0x55, 0xEF, 0x58, 0x81, 0x10, 0x96, 0x87, 0xB3, 0xC9, 0x03, 0x04, 0xCE, 0x9E, 0x67, 0x02, 0x79, 0x85, 0x46, 0xF5, 0xF8, 0xB9, 0xB5, 0x56, 0x97, 0x31, 0x5C, 0xA3, 0x5E, 0x09, 0x9C, 0x36, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].reverse()),
        y: cryptoMath.bytesToDigits([0x20, 0x25, 0xD6, 0xF7, 0x12, 0xCF, 0x5E, 0x9C, 0x4E, 0x92, 0x27, 0x1D, 0xAB, 0x97, 0x41, 0x4E, 0xFF, 0xB9, 0x7D, 0x23, 0x4E, 0xD0, 0xD8, 0x62, 0x18, 0x6B, 0x19, 0xC9, 0xB8, 0x61, 0x45, 0xE7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].reverse())
    }

    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    ecOperator.convertToExtendedProjective(point);
    var p = point.clone();
    var r = point.clone();

    ecOperator.double(p, p);

    for (var i = 0; i < 10; i++) {
        ecOperator.add(r, p, p);
    }

    ecOperator.normalize(p);

    if (p.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (cryptoMath.compareDigits(p.x, expectedValue.x) !== 0) {
        ok(false, "point.x != expectedValue.x");
    }

    if (cryptoMath.compareDigits(p.y, expectedValue.y) !== 0) {
        ok(false, "point.y != expectedValue.y");
    }

    ok(true);
});

