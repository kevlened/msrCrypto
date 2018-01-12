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

/// <reference path="~/scripts/cryptoMath.js" />
/// <reference path="~/scripts/qunit/qunit-1.15.0.js" />

var cryptoMath = cryptoMath || msrCrypto.cryptoMath;

// Create an array, mimics the constructors for typed arrays.
function createArray(/*@dynamic*/parameter) {
    var i, array = null;
    if (!arguments.length || typeof arguments[0] === "number") {
        // A number.
        array = new Array(parameter);
        for (i = 0; i < parameter; i += 1) {
            array[i] = 0;
        }
    } else if (typeof arguments[0] === "object") {
        // An array or other index-able object
        array = new Array(parameter.length);
        for (i = 0; i < parameter.length; i += 1) {
            array[i] = parameter[i];
        }
    }
    return array;
}

// Returns an array of the given length, filled with random digits
// length - Number - The number of random digits to return
getRandomDigits = function (length) {

    var digits = createArray(length);
    var sentinel = cryptoMath.DIGIT_BASE;

    for (var i = 0; i < digits.length; i += 1) {
        digits[i] = Math.floor((Math.random() % 1) * sentinel);
    }

    return digits;
};

module("cryptoUtilityTests");

/**
 * Test powerOfTwo.
 */
test("testPowerOfTwo", function () {
    function testPowerOfTwoImpl(n, expected) {
        var actual = cryptoMath.powerOfTwo(n);
        ok(cryptoMath.sequenceEqual(actual, expected), actual + " = " + expected);
    }

    testPowerOfTwoImpl(0, [1]);
    testPowerOfTwoImpl(1, [2]);
    testPowerOfTwoImpl(2, [4]);
    testPowerOfTwoImpl(3, [8]);
    testPowerOfTwoImpl(4, [16]);
    testPowerOfTwoImpl(5, [32]);
    testPowerOfTwoImpl(6, [64]);
    testPowerOfTwoImpl(7, [128]);
    testPowerOfTwoImpl(8, [1, 0]);
    testPowerOfTwoImpl(15, [0x80, 0x00]);
    testPowerOfTwoImpl(16, [0x01, 0x00, 0x00]);
    testPowerOfTwoImpl(32, [0x01, 0x00, 0x00, 0x00, 0x00]);
});

/**
 * Test computeBitArray.
 */
test("testcomputeBitArray", function () {
    function testComputeBitArrayImpl(a1, expected) {
        var actual = cryptoMath.computeBitArray(a1);
        ok(cryptoMath.sequenceEqual(actual, expected), actual + " = " + expected);
    }

    testComputeBitArrayImpl([0x80], [0, 0, 0, 0, 0, 0, 0, 1]);
    testComputeBitArrayImpl([0x00], []);
    testComputeBitArrayImpl([0x01], [1]);
    testComputeBitArrayImpl([0x01, 0x00], [0, 0, 0, 0, 0, 0, 0, 0, 1]);
    testComputeBitArrayImpl([0x40, 0x00], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
});

/**
 * Test bitLength.
 */
test("testBitLength", function () {
    function testBitLengthImpl(a1, expected) {
        var actual = cryptoMath.bitLength(a1);

        equal(actual, expected, actual + " = " + expected);
    }

    testBitLengthImpl([0x00], 0);
    testBitLengthImpl([0x80], 8);
    testBitLengthImpl([0x40], 7);
    testBitLengthImpl([0x20], 6);
    testBitLengthImpl([0x10], 5);
    testBitLengthImpl([0x08], 4);
    testBitLengthImpl([0x04], 3);
    testBitLengthImpl([0x02], 2);
    testBitLengthImpl([0x01], 1);

    testBitLengthImpl([0x00, 0x00], 0);
    testBitLengthImpl([0x00, 0x80], 8);
    testBitLengthImpl([0x00, 0x00, 0xFF], 8);
    testBitLengthImpl([0xFF, 0x00, 0x00, 0x00], 32);
});
/**
 * Test swapEndianness.
 */
test("testSwapEndianness", function () {
    var byteArray1 = [0, 1, 2, 3, 4, 5];
    var byteArray2 = [5, 4, 3, 2, 1, 0];

    function testSwapEndiannessImpl(a1, expected) {

        var actual = cryptoMath.swapEndianness(a1);
        ok(cryptoMath.sequenceEqual(actual, expected), actual + " = " + expected);
    }

    testSwapEndiannessImpl(byteArray1, byteArray2);
});

/**
 * Test sequenceEqual.
 */
test("testSequenceEqual", function () {
    var array1 = [];
    var array2 = [];
    var array3 = [0];
    var array4 = [0];
    var array5 = [1];
    var byteArray1 = [0, 1, 2, 3, 4, 5];
    var byteArray2 = [0, 1, 2, 3, 4, 5];
    var byteArray3 = [0, 1, 2, 3, 4, 5, 6];
    var byteArray4 = [0, 1, 2, 3, 4, 6];
    var byte16Array1 = [0, 1, 2, 3, 4, 5];
    var byte16Array2 = [0, 1, 2, 3, 4, 5];
    var byte16Array3 = [0, 1, 2, 3, 4, 5, 6];
    var byte16Array4 = [0, 1, 2, 3, 4, 6];

    function testSequenceEqualImpl(a1, a2, expected) {
        var actual = cryptoMath.sequenceEqual(a1, a2);
        equal(actual, expected, "(" + a1 + " = " + a2 + ") = " + expected);
    }

    testSequenceEqualImpl(array1, array2, true);
    testSequenceEqualImpl(array1, array3, false);
    testSequenceEqualImpl(array3, array4, true);
    testSequenceEqualImpl(array3, array5, false);
    testSequenceEqualImpl(byteArray1, byteArray2, true);
    testSequenceEqualImpl(byteArray1, byteArray3, false);
    testSequenceEqualImpl(byteArray1, byteArray4, false);
    testSequenceEqualImpl(byte16Array1, byte16Array2, true);
    testSequenceEqualImpl(byte16Array1, byte16Array3, false);
    testSequenceEqualImpl(byte16Array1, byte16Array4, false);
});

/**
 * Test round trip of BytesToDigits and DigitsToBytes.
 */
test("testRoundTripBytesToDigits", function () {

    function executeTestCase(bytes) {
        var digits = cryptoMath.bytesToDigits(bytes);
        var roundTripBytes = cryptoMath.digitsToBytes(digits);

        // strip leading zeros from bytes array
        // we do this because when we convert from
        // digits back to bytes we will not keep
        // leading zeros.
        var firstNonZeroIndex = 0;
        while (firstNonZeroIndex < bytes.length) {
            if (bytes[firstNonZeroIndex] !== 0) {
                break;
            }

            firstNonZeroIndex += 1;
        }

        // we will want to keep a single zero if the whole
        // array is full of zeros.
        if (bytes.length - firstNonZeroIndex === 0) {
            firstNonZeroIndex -= 1;
        }

        var strippedInputBytes = bytes.slice(firstNonZeroIndex);

        // perform sequence comparison
        var actual = cryptoMath.sequenceEqual(strippedInputBytes, roundTripBytes);
        ok(actual, strippedInputBytes + " = " + roundTripBytes);
    }

    // One byte numbers
    executeTestCase([0]);
    executeTestCase([255]);

    // Several bytes, zeros only, should round-trip as just [0]
    executeTestCase([0, 0, 0]);

    // One digit numbers
    executeTestCase([255, 0, 0, 0]);
    executeTestCase([255, 255, 255, 255]);

    // Several digit numbers
    executeTestCase([1, 0, 255, 255, 4, 7, 32, 255]);
    executeTestCase([255, 255, 255, 255, 255, 255, 255, 255]);

    // Odd lengths
    executeTestCase([1, 0, 255, 255, 4]);
    executeTestCase([255, 255, 255, 255, 255]);

    // A 128-bit prime in big-endian byte form
    var primeP = [236, 233, 96, 6, 82, 144, 186, 162, 204, 38, 84, 93, 120, 118, 81, 11];
    executeTestCase(primeP);
});

/**
 * Test conversion of integers to digit representation.
 */
test("testIntToDigits", function () {

    function executeSingleDigitTestCase(value, minDigits) {
        var i, j, result;

        for (i = minDigits; i < 32; i *= 2) {
            result = cryptoMath.intToDigits(value, i);

            // Check length
            equal(result.length, i, result.length + " = " + i);

            // Check trailing zeros
            for (j = minDigits; j < i; j++) {
                equal(result[j], 0, result[j] + " = " + 0);
            }

            // If our test value fits in the first digit, check its value
            if (minDigits == 1) {
                var actual = minDigits == 1 && result[0];
                equal(actual, value, actual + " = " + value);
            }
        }
    }

    executeSingleDigitTestCase(0, 1);
    executeSingleDigitTestCase(1, 1);
    executeSingleDigitTestCase(32768, 1);
    executeSingleDigitTestCase(65536, 2);
});

/**
 * Test the compare digits helper function
 */
test("testCompareDigits", function () {

    function testCompareDigitsImpl(left, right, areEqual, leftLessThanRight) {
        var actual = cryptoMath.compareDigits(left, right);

        if (areEqual) {
            equal(actual, 0);
        } else {
            if (actual === 0) {
                ok(false, "compareDigits failure - should not have returned equal");
            } else {
                if (leftLessThanRight) {
                    if (actual > 0) {
                        ok(false, "compareDigits failure - should have returned less than zero");
                    }
                } else {
                    if (actual < 0) {
                        ok(false, "compareDigits failure - should have returned greater than zero");
                    }
                }
            }
        }
    }

    function testCompareDigitsFromInts(leftInt, rightInt, areEqual, leftLessThanRight) {
        var left = cryptoMath.intToDigits(leftInt, 8);
        var right = cryptoMath.intToDigits(rightInt, 8);
        testCompareDigitsImpl(left, right, areEqual, leftLessThanRight);
    }

    testCompareDigitsFromInts(0, 0, true/* equal? */, false/* left < right ? */);
    testCompareDigitsFromInts(0, 1, false, true);
    testCompareDigitsFromInts(1, 0, false, false);
    testCompareDigitsFromInts(0, 65536, false, true);
    testCompareDigitsFromInts(65536, 0, false, false);

});

/**
 * Test right shift
 */
test("testRightShift", function () {
    // start with a 32 bit (two 16 bit digits) number
    var bytes = [0x40, 0, 0, 0];
    var digits = cryptoMath.bytesToDigits(bytes);

    // check it, shift, rinse, repeat
    var expected = 1073741824;
    for (var i = 0; i < 32; i++) {
        var actual = parseInt(cryptoMath.digitsToString(digits), 10);
        equal(actual, expected, actual + " = " + expected);
        expected = Math.floor(expected / 2);
        cryptoMath.shiftRight(digits, digits);
    }
});

module("integerGroupTests");

///////////////////////////////////////////////////////////////////////////////
// integerGroupTests namespace object                                        //
// This object will contain functions useful for testing the integer group   //
// object and its related methods.                                           //
///////////////////////////////////////////////////////////////////////////////
var integerGroupTests = integerGroupTests || {};

// NIST P-256 modulus
integerGroupTests.p256modulus = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
                                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

// p256 group
integerGroupTests.group256 = new cryptoMath.IntegerGroup(integerGroupTests.p256modulus, true);

// 2048 bit prime
var modulus2048LittleEndian = [239, 96, 205, 120, 155, 4, 191, 213, 214, 251, 67, 138, 69, 64, 158, 141, 4, 123, 139, 208, 158, 3, 244, 36, 205, 238, 58, 58, 41, 41, 16, 116, 136, 85, 134, 60, 223, 157, 143, 24, 156, 128, 242, 219, 84, 31, 230, 24, 164, 221, 207, 167, 71, 187, 15, 148, 236, 104, 51, 37, 223, 52, 167, 248, 179, 21, 126, 224, 201, 237, 171, 127, 235, 176, 217, 8, 50, 169, 226, 111, 12, 189, 124, 243, 3, 0, 215, 32, 225, 77, 228, 19, 201, 164, 114, 243, 146, 70, 159, 191, 190, 196, 113, 130, 103, 173, 12, 249, 243, 31, 228, 138, 87, 251, 118, 124, 114, 157, 142, 38, 1, 176, 154, 96, 29, 141, 53, 201, 115, 164, 44, 208, 68, 152, 224, 221, 200, 84, 142, 25, 252, 91, 207, 225, 32, 162, 70, 219, 236, 60, 167, 155, 72, 163, 135, 196, 247, 237, 96, 33, 103, 245, 249, 93, 220, 254, 109, 136, 120, 157, 53, 174, 235, 91, 75, 26, 60, 83, 67, 35, 201, 76, 28, 198, 188, 184, 145, 33, 141, 202, 217, 70, 253, 235, 183, 178, 162, 234, 163, 167, 37, 195, 70, 148, 61, 150, 237, 226, 68, 15, 251, 190, 66, 98, 209, 121, 168, 103, 203, 48, 199, 220, 126, 68, 220, 44, 157, 209, 232, 131, 235, 102, 241, 9, 250, 148, 40, 91, 46, 48, 242, 118, 168, 52, 168, 88, 109, 29, 205, 247, 249, 72, 185, 2, 12, 154];
integerGroupTests.test2048BitModulus = modulus2048LittleEndian.reverse();
integerGroupTests.group2048 = new cryptoMath.IntegerGroup(integerGroupTests.test2048BitModulus, true);

module("cryptoMathVectorTest");

var cryptoMathVectorTest = {
    startTest: 0, // useful for running select tests
    numTests: 72,
    testVectorDirectory: "../scripts/testVectors/math",
    filePrefix: "jsCryptoTestVector_",
    fileSuffix: ".txt",
    // Read a byte array in comma delimited format into a Uint8Array
    readByteArray: function (string) {
        return string.split(',');
    },
    // Read an int32 array in comma delimited format into a Int32Array
    readIntArray: function (string) {
        var elements = string.split(',');
        var array = createArray(elements.length);

        for (var i = 0; i < elements.length; i++) {
            var number = parseInt(elements[i]);
            array[i] = number;
        }

        var result = array;
        return result;
    }
};

var testDescription = "";

var testid = 0;

var testData;

var request = new XMLHttpRequest();

for (var testNumber = cryptoMathVectorTest.startTest; testNumber < cryptoMathVectorTest.numTests; testNumber++) {
    var i = testid;

    var testVectorFileName = cryptoMathVectorTest.filePrefix +
                             i.toString() +
                             cryptoMathVectorTest.fileSuffix;

    request.open("GET", cryptoMathVectorTest.testVectorDirectory + "/" + testVectorFileName, false);
    request.send(null);

    testData = request.responseText;

    ++testid;

    if (request.status === 200) {
        // Execute the vector test set
        test("executeVectorTests " + testNumber, function () {

            var lines = testData.split('\r\n');

            var testname = lines[0];
            testDescription = lines[1];

            var testRoutine = cryptoMathVectorTest[testname];
            testRoutine.call(this, lines);

        });
    }
}

// A do nothing test, useful for skipping tests
cryptoMathVectorTest.nullTest = function (lines) {
};

// Low Level Add Vector Test
cryptoMathVectorTest.lowleveladd = function (lines) {
    for (var i = 2; i < lines.length; i += 4) {
        // Parse test case.
        // Test vectors are 16-bit aligned; carry bit belongs to the next 16-bit aligned "word"
        // independent from the actual DIGIT size.
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);
        var cBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);
        // Fill up with zero till c.length >= {a.length,b.length}, then append carry
        while (cBytes.length < aBytes.length || cBytes.length < bBytes.length) {
            cBytes.unshift("0");
        }
        cBytes.unshift(lines[i + 3]);

        // Create arguments
        var a = cryptoMath.bytesToDigits(aBytes);
        var b = cryptoMath.bytesToDigits(bBytes);
        var c = cryptoMath.bytesToDigits(cBytes);
        cryptoMath.normalizeDigitArray(c);

        // Do it
        var actual = [0];
        cryptoMath.add(a, b, actual);
        cryptoMath.normalizeDigitArray(actual);

        // Check result
        if (cryptoMath.compareDigits(actual, c) !== 0) {
            ok(false, "Low Level Add vector test failed");
        }
    }
    ok(true, testDescription + ": passed");
};

// Low Level Sub Vector Test
cryptoMathVectorTest.lowlevelsub = function (lines) {
    for (var i = 2; i < lines.length; i += 4) {
        // Parse test case
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);
        var cBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);
        var carry = parseInt(lines[i + 3]);
        while ((cBytes.length % cryptoMath.DIGIT_NUM_BYTES) !== 0) {
            cBytes.unshift(carry === 0 ? "0" : "255");
        }

        // Create arguments
        var a = cryptoMath.bytesToDigits(aBytes);
        var b = cryptoMath.bytesToDigits(bBytes);
        var c = cryptoMath.bytesToDigits(cBytes);

        // Properly size the arrays as if they were fixed width
        // field elements to compensate for fixed-length test vectors.
        var size = Math.max(a.length, b.length);
        cryptoMath.normalizeDigitArray(a, size, true);
        cryptoMath.normalizeDigitArray(b, size, true);
        cryptoMath.normalizeDigitArray(c, size, true);

        // Do it
        var actual = [0];
        var carryActual = cryptoMath.subtract(a, b, actual);
        cryptoMath.normalizeDigitArray(c);
        cryptoMath.normalizeDigitArray(actual);

        // Check result
        if (cryptoMath.compareDigits(actual, c) !== 0) {
            ok(false, "Low Level Sub vector test failed");
        }

        if (carry !== carryActual) {
            ok(false, "Low Level Sub vector test failed");
        }
    }
    ok(true, testDescription + ": passed");
};

// Fp Modular Addition Vector Test
cryptoMathVectorTest.fpmodadd = function (lines) {
    // Get the modulus and construct the group
    var modulusBytes = cryptoMathVectorTest.readByteArray(lines[2]);
    var group = cryptoMath.IntegerGroup(modulusBytes);

    // Loop through the test cases
    for (var i = 3; i < lines.length; i += 3) {
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);
        var cBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);

        var a = group.createElementFromBytes(aBytes);
        var b = group.createElementFromBytes(bBytes);
        var c = group.createElementFromBytes(cBytes);

        var actual = group.createElementFromInteger(0);

        group.add(a, b, actual);

        if (!actual.equals(c)) {
            ok(false, "ModAdd vector test failed");
        }
    }

    ok(true, testDescription + ": passed");
};

// Fp Modular Subtraction Vector Test
cryptoMathVectorTest.fpmodsub = function (lines) {
    // Get the modulus and construct the group object
    var modulusBytes = cryptoMathVectorTest.readByteArray(lines[2]);
    var group = new cryptoMath.IntegerGroup(modulusBytes);

    // Loop through test cases
    for (var i = 3; i < lines.length; i += 3) {
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);
        var cBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);

        var a = group.createElementFromBytes(aBytes);
        var b = group.createElementFromBytes(bBytes);
        var c = group.createElementFromBytes(cBytes);

        var actual = group.createElementFromInteger(0);

        group.subtract(a, b, actual);

        if (!actual.equals(c)) {
            ok(false, "ModSub vector test failed");
        }
    }

    ok(true, testDescription + ": passed");
};

// Division Vector Test
cryptoMathVectorTest.division = function (lines) {

    // Loop through test cases
    for (var i = 2; i < lines.length; i += 4) {

        // Read arguments as big endian byte arrays
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);

        // Read expected results as big endian byte arrays
        var cBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);
        var dBytes = cryptoMathVectorTest.readByteArray(lines[i + 3]);

        // Convert to digit arrays
        var aDigits = cryptoMath.bytesToDigits(aBytes);
        var bDigits = cryptoMath.bytesToDigits(bBytes);

        // Determine the required size of our working arrays
        var n = Math.max(aDigits.length, bDigits.length);

        // Convert expected answers to digits and resize arrays
        var cDigits = cryptoMath.bytesToDigits(cBytes);
        var dDigits = cryptoMath.bytesToDigits(dBytes);

        // Create temp arrays and result arrays
        var tmp1 = createArray(n);
        var tmp2 = createArray(n);
        var actualQuotient = createArray(n);
        var actualRemainder = createArray(n);

        // Perform the calculation
        cryptoMath.divRem(aDigits, bDigits, actualQuotient, actualRemainder, tmp1, tmp2);

        // Verify the results
        if (cryptoMath.compareDigits(actualQuotient, cDigits) !== 0) {
            ok(false, "Division vector test failed - quotient incorrect");
        }

        if (cryptoMath.compareDigits(actualRemainder, dDigits) !== 0) {
            ok(false, "Division vector test failed - remainder incorrect");
        }
    }
    ok(true, testDescription + ": passed");
};

cryptoMathVectorTest.modmulCIOS = function (lines) {

    // Get the modulus and construct the group object
    var modulusBytes = cryptoMathVectorTest.readByteArray(lines[2]);

    // create montgomery multiplier
    var modulusDigits = cryptoMath.bytesToDigits(modulusBytes);
    var mul = new cryptoMath.MontgomeryMultiplier(modulusDigits);

    // conversion value from 16-bit digit test vector to variable digit length.
    // Multiply the computed result by 2^(DIGIT_BITS - (modulus.length % DIGIT_BITS)) and reduce by the modulus.
    // Note: powerOfTwo returns big endian byte array.
    var conversion = (cryptoMath.DIGIT_BITS - 8 * (modulusBytes.length % cryptoMath.DIGIT_NUM_BYTES)) % cryptoMath.DIGIT_BITS;
    if (conversion >= 0) {
        conversion = cryptoMath.bytesToDigits(cryptoMath.powerOfTwo(conversion));
    }
    else {
        // If the active digit length is shorter than 16 bits.
        cryptoMath.modInv(cryptoMath.bytesToDigits(cryptoMath.powerOfTwo(-conversion)), modulusDigits, conversion);
    }

    // Loop through test cases
    for (var i = 3; i < lines.length; i += 3) {
        // CAUTION: The known results in the test vectors assume 16 bit digits.
        //          Thus, the Montgomeryized results would not match if digit length in the math library is changed.
        //          In order to match, the computed result actualDigits ust be multiplied by a constant conversion.
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);
        var resultBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);

        var aDigits = cryptoMath.bytesToDigits(aBytes);
        var bDigits = cryptoMath.bytesToDigits(bBytes);
        var resultDigits = cryptoMath.bytesToDigits(resultBytes);

        cryptoMath.normalizeDigitArray(aDigits, mul.s, true);
        cryptoMath.normalizeDigitArray(bDigits, mul.s, true);
        cryptoMath.normalizeDigitArray(resultDigits, mul.s, true);

        var actualDigits = createArray(resultDigits.length);

        // Perform montgomery multiplication
        // Note: The test vectors DO NOT convert into or out of montgomery form
        // that is to say, this is simply RAW cios multiplication.
        mul.montgomeryMultiply(aDigits, bDigits, actualDigits);
        cryptoMath.modMul(actualDigits, conversion, modulusDigits, actualDigits);

        if (cryptoMath.compareDigits(actualDigits, resultDigits) !== 0) {
            ok(false, "ModMulCIOS vector test failed");
        }
    }
    ok(true, testDescription + ": passed");
};

cryptoMathVectorTest.modexp = function (lines) {

    // Get the modulus and construct the group object
    var modulusBytes = cryptoMathVectorTest.readByteArray(lines[2]);

    // create montgomery multiplier
    var modulusDigits = cryptoMath.bytesToDigits(modulusBytes);
    var mul = new cryptoMath.MontgomeryMultiplier(modulusDigits);

    // Loop through test cases
    for (var i = 3; i < lines.length; i += 3) {
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var bBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);
        var resultBytes = cryptoMathVectorTest.readByteArray(lines[i + 2]);

        var aDigits = cryptoMath.bytesToDigits(aBytes);
        var bDigits = cryptoMath.bytesToDigits(bBytes);
        var resultDigits = cryptoMath.bytesToDigits(resultBytes);

        // a and result must be the same width
        cryptoMath.normalizeDigitArray(aDigits, mul.s, true);
        cryptoMath.normalizeDigitArray(resultDigits, mul.s, true);

        var actualDigits = createArray(resultDigits.length);

        // Perform modular exponentiation
        mul.modExp(aDigits, bDigits, actualDigits);

        if (cryptoMath.compareDigits(actualDigits, resultDigits) !== 0) {
            ok(false, "ModExp vector test failed");
        }
    }

    ok(true, testDescription + ": passed");
};

cryptoMathVectorTest.shiftright = function (lines) {

    // Loop through test cases
    for (var i = 2; i < lines.length; i += 2) {
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var resultBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);

        var aDigits = cryptoMath.bytesToDigits(aBytes);
        var resultDigits = cryptoMath.bytesToDigits(resultBytes);

        // a and result must be the same width
        cryptoMath.normalizeDigitArray(resultDigits, aDigits.length, true);

        var actualDigits = createArray(resultDigits.length);

        // Perform right shift
        cryptoMath.shiftRight(aDigits, actualDigits);

        if (!cryptoMath.sequenceEqual(actualDigits, resultDigits)) {
            ok(false, "Right shift vector test failed");
        }
    }

    ok(true, testDescription + ": passed");
};

// Fp Modular Inversion Vector Test
cryptoMathVectorTest.fpmodinv = function (lines) {

    // Get the modulus and construct the group
    var modulusBytes = cryptoMathVectorTest.readByteArray(lines[2]);
    var group = new cryptoMath.IntegerGroup(modulusBytes);

    // Loop through the test cases
    for (var i = 3; i < lines.length; i += 2) {
        var aBytes = cryptoMathVectorTest.readByteArray(lines[i]);
        var expectedBytes = cryptoMathVectorTest.readByteArray(lines[i + 1]);

        // create element objects of the operand and result
        var a = group.createElementFromBytes(aBytes);
        var expected = group.createElementFromBytes(expectedBytes);

        // element to recieve the result
        var actual = group.createElementFromInteger(0);

        // perform the operation
        group.inverse(a, actual);

        // check the answer
        if (!actual.equals(expected)) {
            ok(false, "ModInv vector test failed");
        }
    }

    ok(true, testDescription + ": passed");
};

