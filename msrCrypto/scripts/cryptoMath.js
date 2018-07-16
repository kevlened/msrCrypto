//*******************************************************************************
//
//    Copyright 2018 Microsoft
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

/// #region JSCop/JsHint
/* jshint -W016 */ /* allows bitwise operators */
/* jshint -W052 */ /* allows not operator */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="random.js" />

/// <dictionary>alg,bitmasks,coord,De-montgomeryized,digitbits,digitmask,divrem,Elt,endian-ness,endian,gcd,goto,Int,Jacobian,Legendre,mlen,Modm,modpow,montgomerized,montgomeryize,montgomeryized,montmul,mul,param,Pomerance,povar,precompute,Pseudocode,Tolga,typeof,Uint,unrollsentinel,wil,Xout,Xout-t,Yout,Zout</dictionary>
/// <dictionary>aequals,Eshift,idx,Lsbit,Minust,mult,myelement,myresult,naf,Neg,Nist,numcopy,Obj,onemontgomery,Precomputation,Res,swaptmp,Tmp,xbytes,ybytes</dictionary>

/// #endregion JSCop/JsHint

function msrcryptoMath() {
    // 'number' of bits per digit. Must be even.
    var DIGIT_BITS = 24;
    // 'number' of bytes per digit.
    var DIGIT_NUM_BYTES = Math.floor(DIGIT_BITS / 8);
    // digit mask.
    var DIGIT_MASK = (1 << DIGIT_BITS) - 1;
    // digit base.
    var DIGIT_BASE = (1 << DIGIT_BITS);
    // max digit value, unsigned
    var DIGIT_MAX = DIGIT_MASK;

    // Construct scaler for DIGIT_NUM_BYTES, so I don't have to multiply in the loop
    var DIGIT_SCALER = [1, 256];
    for (var i = 2; i <= DIGIT_NUM_BYTES; i++) {
        DIGIT_SCALER[i] = DIGIT_SCALER[i - 1] * 256;
    }

    // Number of trailing zero bits in numbers 0..15 (4 bits). [0] is for 0, [15] is for 15.
    var Zero = [0];
    var One = [1];

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

    function swapEndianness(bytes) {
        /// <summary>Swap big endian bytes to little endian bytes.</summary>
        /// <param name="bytes" type="Bytes">UInt8Array - representing a big-integer.</param>
        /// <returns type="Bytes">UInt8Array - the number with endianness swapped.</returns>

        var out = new Array(bytes.length);
        var i = 0;

        while (i < bytes.length) {
            out[i] = bytes[bytes.length - i - 1];
            i += 1;
        }

        return out;
    }

    function stringToDigits(number, radix) {
        /// <summary>Parse a String in a given base into a little endian digit array.</summary>
        /// <param name="number" type="String">Input unsigned integer in a string.</param>
        /// <param name="radix" optional="true" integer="true">
        /// <![CDATA[ Radix of the input. Must be >=2 and <=36. Default = 10. ]]>
        /// </param>
        /// <returns type="Array">Array of digits in little endian; [0] is LSW.</returns>

        // skip leading and trailing whitespace.
        number = number.replace(/^\s+|\s+$/g, '');
        var num = [0];
        var buffer = [0];
        radix = radix || 10;        // default radix is 10
        for (var i = 0; i < number.length; i += 1) {
            // Extract character
            var char = parseInt(number[i], radix);
            if (isNaN(char)) {
                throw new Error("Failed to convert string to integer in radix " + radix.toString());
            }

            // 'buffer' = 'num' * 'radix'
            multiply(num, radix, buffer);

            // 'num' = 'buffer' + 'char'
            add(buffer, [/*@static_cast(Number)*/char], num);
            normalizeDigitArray(num);
        }

        return num;
    }

    function digitsToString(digits, radix) {
        /// <summary>Convert a big-endian byte array to a number in string in radix.</summary>
        /// <param name="digits" type="Digits">A big integer as a little-endian digit array.</param>
        /// <param name="radix" optional="true" integer="true">Radix from 2 to 26. Default = 10.</param>
        /// <returns type="String">The number in base radix as a string.</returns>

        radix = radix || 10;
        if (DIGIT_BASE <= radix) {
            throw new Error("DIGIT_BASE is smaller than RADIX; cannot convert.");
        }

        var wordLength = digits.length;
        var quotient = [];
        var remainder = [];
        var temp1 = [];
        var temp2 = [];
        var divisor = [];
        var a = [];
        var i;

        // Find the largest divisor that fits in a digit in radix
        //divisor[0] = 10000; // Largest power of ten fitting in a digit
        var sb = "";
        var pad = "0";
        divisor[0] = radix;
        while (Math.floor(DIGIT_BASE / divisor[0]) >= radix) {
            divisor[0] = divisor[0] * radix;
            pad = pad.concat("0");
        }

        for (i = 0; i < wordLength; i += 1) {
            a[i] = digits[i];
        }

        do {
            var allZeros = true;
            for (i = 0; i < a.length; i += 1) {
                if (a[i] !== 0) {
                    allZeros = false;
                    break;
                }
            }

            if (allZeros) {
                break;
            }

            divRem(a, divisor, quotient, remainder, temp1, temp2);
            normalizeDigitArray(quotient, a.length, true);

            var /*@type(String) */ newDigits = remainder[0].toString(radix);
            sb = pad.substring(0, pad.length - newDigits.length) + newDigits + sb;

            var swap = a;
            a = quotient;
            quotient = swap;
        } while (true);

        // Trim leading zeros
        while (sb.length !== 0 && sb[0] === "0") {
            sb = sb.substring(1, sb.length);
        }

        if (sb.length === 0) {
            sb = "0";
        }

        return sb;
    }

    function powerOfTwo(i) {
        /// <summary>Given a positive integer i, return a big integer in big-endian format
        ///   equal to 2^i. This is useful for creating fields of certain size.</summary>
        /// <param name="i" type="Number">A positive integer.</param>
        /// <returns>UInt8Array - 2^i as a big-endian byte array.</returns>
        var requiredBytes = Math.ceil((i + 1) / 8);
        var out = createArray(requiredBytes);
        out[0] = Math.pow(2, i % 8);
        return out;
    }

    function computeBitArray(bytes) {
        /// <summary>Given an array of bytes in big-endian format, compute UInt8Array with
        /// one element for each bit (0 or 1), in little-endian order.</summary>
        /// <param name="bytes" type="Digits">An array of bytes in big-endian format.</param>
        /// <returns type="Digits">An array of 0's and 1's representing the bits in little-endian.</returns>

        var out = createArray(bytes.length * 8);
        var bitLength = 0;
        var i = bytes.length - 1;
        while (i >= 0) {
            var j = 0;
            while (j < 8) {
                var mask = (1 << j);
                var bit = ((bytes[i] & mask) === mask) ? 1 : 0;
                var thisBitIndex = (8 * ((bytes.length - i) - 1)) + j;

                if (bit === 1) {
                    bitLength = thisBitIndex + 1;
                }

                out[thisBitIndex] = bit;
                j += 1;
            }

            i--;
        }

        return out.slice(0, bitLength);
    }

    function bitScanForward(value) {
        /// <summary>Return the 0-based index of the first non-zero bit starting at the most significant bit position.</summary>
        /// <param name="value" type="Number" integer="true">Value to scan.</param>
        /// <returns>Zero-based index of the first non-zero bit.</returns>
        var mask = DIGIT_BASE >>> 1;
        var index = DIGIT_BITS;
        while (index-- > 0) {
            if ((value & mask) === mask) {
                break;
            }
            mask = mask >>> 1;
        }

        return index;
    }

    function highestSetBit(bytes) {
        /// <summary>Returns the (1 indexed) index of the highest set bit.</summary>
        /// <param name="bytes" type="Array">A big-endian big integer byte array.</param>
        /// <returns type="Number">The index of the highest bit.</returns>

        var i = 0;
        var bitLength = 0;

        while (i < bytes.length) {
            if (bitLength === 0) {
                // Look for highest set bit in this byte
                var j = 7;
                while (j >= 0 && bitLength === 0) {
                    var mask = (1 << j);
                    if ((bytes[i] & mask) === mask) {
                        bitLength = j + 1;
                    }

                    j--;
                }
            } else {
                bitLength += 8;
            }

            i += 1;
        }

        return bitLength;
    }

    function fixedWindowRecode(digits, windowSize, t) {
        /// <summary></summary>
        /// <param name="digits" type="Array">Digits to recode</param>
        /// <param name="windowSize" type="Number">Window size</param>
        /// <returns type="Array">Recoded digits</returns>}

        // Make a copy of digits because we are going to modify it with shifts below.
        digits = digits.slice();

        var recodedDigits = [],
            windowSizeBits = Math.pow(2, windowSize),
            windowSizeMinus1Bits = Math.pow(2, windowSize - 1);

        for (var i = 0; i < t; i++) {

            // k_digits[i] := (Z!k mod 2^w) - 2^(w-1);
            recodedDigits[i] = (digits[0] % windowSizeBits) - windowSizeMinus1Bits;

            // k := (k - k_digits[i])/2^(w-1);
            digits[0] = digits[0] - recodedDigits[i];

            // PERF : can probably do this faster
            cryptoMath.shiftRight(digits, digits, windowSize - 1);
        }

        recodedDigits[i] = digits[0];

        return recodedDigits;
    }

    function fetchBits(digits, startBit, count) {
        /// <summary>From an array of digits, return a sequential set of bits.</summary>
        /// <param name="digits" type=""></param>
        /// <param name="start" type=""></param>
        /// <param name="end" type=""></param>

        var startDigit = Math.floor(startBit / cryptoMath.DIGIT_BITS);
        var endDigit = startDigit + 1;

        var shiftRight = (startBit % cryptoMath.DIGIT_BITS);
        var shiftLeft = cryptoMath.DIGIT_BITS - shiftRight;

        var bits = (digits[startDigit] >>> shiftRight) | (digits[endDigit] << shiftLeft);

        return bits & (cryptoMath.DIGIT_MASK >>> (cryptoMath.DIGIT_BITS - count));

    }

    function fetchBits2(digits, startBit, count) {
        /// <summary>From an array of digits, return a sub-set of bits from an arbitray index.</summary>
        /// <param name="digits" type="Array">Array of digits</param>
        /// <param name="startBit" type="Number">Zero-index position of start bit</param>
        /// <param name="count" type="Number">Number of bits to return</param>
        /// <returns type="Number">Value of n-bits</returns>

        var startDigit = Math.floor(startBit / DIGIT_BITS),
            shiftRight = (startBit % DIGIT_BITS);

        return (digits[startDigit] >>> shiftRight) |
            (digits[startDigit + 1] << (DIGIT_BITS - shiftRight))
            & (DIGIT_MASK >>> (DIGIT_BITS - count));
    }

    function copyArray(/*@Array*/source, sourceIndex, /*@Array*/destination, destIndex, length) {
        /// <summary>Copies a range of elements from one array to another array.</summary>
        /// <param name="source" type="Array">Source array to copy from.</param>
        /// <param name="sourceIndex" type="Number">The index in the source array at which copying begins.</param>
        /// <param name="destination" type="Array">The array that receives the data.</param>
        /// <param name="destIndex" type="Number">The index in the destination array at which storing begins.</param>
        /// <param name="length" type="Number">The number of elements to copy.</param>
        while (length-- > 0) {
            destination[destIndex + length] = source[sourceIndex + length];
        }
    }

    function isZero(array) {
        /// <summary>Check if an array is zero. All elements are zero.</summary>
        /// <param name="array" type="Digits">UInt16Array - An array to be checked.</param>
        /// <returns type="Boolean"/>
        var i;
        for (i = 0; i < array.length; i += 1) {
            if (array[i] !== 0) {
                return false;
            }
        }
        return true;
    }

    function isEven(array) {
        /// <summary>Returns true if this number is even.</summary>
        /// <param name="array" type="Digits"/>
        /// <returns type="Boolean"/>
        return (array[0] & 0x1) === 0x0;
    }

    function sequenceEqual(left, right) {
        /// <summary>Compare two indexable collections for sequence equality.</summary>
        /// <param name="left" type="Digits">The left array.</param>
        /// <param name="right" type="Digits">The right array.</param>
        /// <returns type="Boolean">True if both arrays are the same.</returns>
        if (left.length !== right.length) {
            return false;
        }

        for (var i = 0; i < left.length; i += 1) {
            if (left[i] !== right[i]) {
                return false;
            }
        }

        return true;
    }

    function bytesToDigits(bytes) {
        /// <summary>Convert an unsigned number from big-endian bytes to little endian digits.</summary>
        /// <param name="bytes" type="Bytes">The number in unsigned big-endian byte format.</param>
        /// <returns type="Array">The digits in little-endian.</returns>

        // Construct scaler for DIGIT_NUM_BYTES, so I don't have to multiply in the loop
        var arrayLength = Math.floor((bytes.length + DIGIT_NUM_BYTES - 1) / DIGIT_NUM_BYTES);
        var array = new Array(arrayLength);
        array[0] = 0;
        var digit = 0, index = 0, scIndex = 0;
        for (var i = bytes.length - 1; i >= 0; i--) {
            digit = digit + (DIGIT_SCALER[scIndex++] * (bytes[i] & 0x0ff));
            if (DIGIT_SCALER[scIndex] === DIGIT_BASE) {
                scIndex = 0;
                array[index++] = digit;
                digit = 0;
            }
        }

        // Last digit (MSW), if there is a need
        if (digit !== 0) {
            array[index] = digit;
        }

        // Replace potential undefined elements with zeros
        while (array[--arrayLength] == null) array[arrayLength] = 0;

        return array;
    }

    function digitsToBytes(digits, trim, minTrimLength) {
        /// <summary>Construct a big endian array of bytes from a litte-endian array of digits. 
        /// Always returns at least one byte and trims leading zeros.</summary>
        /// <param name="digits" type="Array">The digits in little-endian.</param>
        /// <param name="trim" type="Boolean" optional="true">Remove the leading zeros from the result (default true)</param>
        /// <param name="minTrimLength" type="Number" optional="true">Minimum length to trim down to. Valid only if trim is true. Default=1.</param>
        /// <returns type="Array">Encoded bytes in big-endian format.</returns>

        var i, j, byte1;
        var bytes = [0];

        if (typeof trim === "undefined") {
            trim = true;
        }

        for (i = 0; i < digits.length; i += 1) {
            byte1 = digits[i];
            for (j = 0; j < DIGIT_NUM_BYTES; j += 1) {
                bytes[i * DIGIT_NUM_BYTES + j] = byte1 & 0x0FF;
                byte1 = Math.floor(byte1 / 256);
            }
        }

        bytes = swapEndianness(bytes);

        if (minTrimLength === undefined) {
            minTrimLength = 1;
        }
        if (trim) {
            while (bytes.length > minTrimLength && bytes[0] === 0) {
                bytes.shift();
            }
        }

        return bytes;
    }

    function intToDigits(value, numDigits) {
        /// <summary>Construct an array of digits from a positive integer.</summary>
        /// <param name="value" type="Number" integer="true">A positive integer to be converted to digit form.</param>
        /// <param name="numDigits" type="Number" optional="true" integer="true">The number of digits to use for the digit form.</param>
        /// <returns type="Array">The given integer in digit form.</returns>

        if (typeof numDigits === "undefined") {
            if (value <= 1) {
                numDigits = 1; // Special case <= 1
            } else {
                var numBits = Math.log(value) / Math.LN2;
                numDigits = Math.ceil(numBits / DIGIT_BITS);
            }
        }

        var digitRepresentation = [];
        while (value > 0) {
            digitRepresentation.push(value % DIGIT_BASE);
            value = Math.floor(value / DIGIT_BASE);
        }

        while (digitRepresentation.length < numDigits) {
            digitRepresentation.push(0);
        }

        return digitRepresentation;
    }

    function mswIndex(digits) {
        /// <summary>Return the index of the most significant word of x, 0-indexed.
        /// If x is zero (no significant index), then -1 is returned.</summary>
        /// <param name="digits" type="Array">Digit array.</param>
        /// <returns type="Number">Index of the most significant word, or -1 if digits is zero.</returns>
        for (var i = digits.length - 1; i >= 0; i--) {
            if (digits[i] !== undefined && digits[i] !== 0) {
                return i;
            }
        }

        return (digits[0] === 0) ? -1 : 0;
    }

    function compareDigits(left, right) {
        /// <summary>Compare two digit arrays by value. Returns an integer indicating the comparison result.
        /// Digit arrays are in little endian.</summary>
        /// <param name="left" type="Array">The object on the left side of the comparison.</param>
        /// <param name="right" type="Array">The object on the right side of the comparison.</param>
        /// <returns type="Number">A value that indicates the relative order of the objects 
        ///                           being compared. The value is 0 if the items are equal, 
        ///                           negative if the left object precedes the right object,
        ///                           and positive otherwise.</returns>

        var comparisonResult = 0;
        var nLeft = mswIndex(left) + 1;
        var nRight = mswIndex(right) + 1;
        if (nLeft > nRight) {
            comparisonResult = 1;
        } else if (nRight > nLeft) {
            comparisonResult = -1;
        } else {
            while ((nLeft-- > 0) && (comparisonResult === 0)) {
                comparisonResult = left[nLeft] - right[nLeft];
            }
        }

        return comparisonResult;
    }

    function normalizeDigitArray(digits, length, pad) {
        /// <summary>Normalize a digit array by truncating any leading zeroes and adjusting its length.
        /// Set the length if given, and pad it with zeroes to that length of padding is requested.</summary>
        /// <remarks>Normalization results with a zero-indexed length of the array such that the MSW is not zero.
        /// If the final array length is zero and no non-zero digits are found, assign digits[0]=0 and set length to 1.
        /// Optionally, pad with zeroes to the given length, and set the array length.</remarks>
        /// <param name="digits" type="Array">Digit array.</param>
        /// <param name="length" type="Number" integer="true" optional="true">Output length to pad with zeroes.</param>
        /// <param name="pad" type="Boolean" optional="true">Pad with zeroes to length if true [false].</param>
        /// <returns type="Array">Resized digits array; same input object.</returns>

        // Trim. Find the trimmed length and the position to start padding from (if padding is requested).
        var i = mswIndex(digits);

        // set the length to the given length (if given) or the trimmed length
        digits.length = length || i + 1;

        // Pad to the length
        if (pad) {
            while (++i < digits.length) {
                digits[i] = 0;
            }
        }

        if (digits.length <= 0) {
            // no non-zero digits found.
            digits[0] = 0;
            digits.length = 1;
        }

        return digits;
    }

    function shiftRight(source, destination, bits, length) {
        /// <summary>Shift a big integer to the right by the given number of bits or 1 if bits is not specified,
        /// effectively dividing by two (or 2^bits) and ignoring the remainder.</summary>
        /// <param name="source" type="Array">Source digit array.</param>
        /// <param name="destination" type="Array">Destination digit array. May be the same as source.</param>
        /// <param name="bits" integer="true" optional="true">Number of bits to shift, must be less than DIGIT_BITS and greater or equal to zero. Default is 1.</param>
        /// <param name="length" optional="true" integer="true">Number of items to shift from he source array. Default is source.length.</param>
        /// <remarks>This is a numerical shift. Integers are stored in arrays in little-endian format.
        /// Thus, this function shifts an array from higher order indices into lower indices. [0] is LSW.
        /// </remarks>

        if (bits === undefined) {
            bits = 1;
        } else if (bits >= DIGIT_BITS || bits < 0) {
            throw new Error("Invalid bit count for shiftRight");
        }
        if (length === undefined) {
            length = source.length;
        }

        var n = length - 1;
        var leftShiftBitCount = DIGIT_BITS - bits;
        for (var i = 0; i < n; i++) {
            destination[i] = ((source[i + 1] << leftShiftBitCount) | (source[i] >>> bits)) & DIGIT_MASK;
            //a[i] = high|low = low bits of a[i+1] | high bits of a[i]
        }

        destination[n] = source[n] >>> bits;
    }

    function shiftLeft(source, destination, bits, length) {
        /// <summary>Shift a number array to the left by given bits, i.e., multiply by 2^bits.</summary>
        /// <param name="source" type="Array">Source digit array.</param>
        /// <param name="destination" type="Array">Destination digit array. May be the same as source.</param>
        /// <param name="bits" integer="true" optional="true">Number of bits to shift, must be less than DIGIT_BITS and greater or equal to zero. Default is 1.</param>
        /// <param name="length" optional="true" integer="true">Number of items to shift from he source array. Default is source.length.</param>
        /// <remarks>An additional MSW digit may be added if the leftshift out from the current MSW produces a non-zero result. [0] is LSW.</remarks>

        if (bits === undefined) {
            bits = 1;
        } else if (bits >= DIGIT_BITS || bits < 0) {
            throw new Error("bit count must be smaller than DIGIT_BITS and positive in shiftLeft");
        }
        if (length === undefined) {
            length = source.length;
        }

        var rightShiftBitCount = DIGIT_BITS - bits;
        // The following line is correct. destination should remain undefined if there are no bits going into it.
        destination[length] = (source[length - 1] >>> (DIGIT_BITS - bits)) || destination[length];
        for (var i = length - 1; i > 0; i--) {
            destination[i] = ((source[i] << bits) | ((source[i - 1] >>> rightShiftBitCount))) & DIGIT_MASK;
            // a[i] = high|low = low bits of a[i] | high bits of a[i-1]
        }

        destination[0] = (source[0] << bits) & DIGIT_MASK;
    }

    //// //// //// //// //// //// //// //// //// //// //// //// //// /
    // Low level math routines
    //// //// //// //// //// //// //// //// //// //// //// //// //// /

    function add(addend1, addend2, sum) {
        /// <summary>Add two arrays of digits into a third array: sum = addend1 + addend2. Carry is recorded in the output if there is one.</summary>
        /// <param name="addend1" type="Array">The first addend.</param>
        /// <param name="addend2" type="Array">The second added.</param>
        /// <param name="sum" type="Array">The output sum buffer addend1 + addend2.</param>
        /// <returns type="Number" integer="true">If carry out then 1, otherwise 0.</returns>

        // Determine which is shorter
        var shortArray = addend1;
        var longArray = addend2;
        if (addend2.length < addend1.length) {
            shortArray = addend2;
            longArray = addend1;
        }

        // Perform the addition
        var s = shortArray.length;
        var carry = 0;
        var i;

        for (i = 0; i < s; i += 1) {
            carry += shortArray[i] + longArray[i];
            sum[i] = carry & DIGIT_MASK;
            carry = (carry >> DIGIT_BITS);
        }

        for (i = s; i < longArray.length; i += 1) {
            carry += longArray[i];
            sum[i] = carry & DIGIT_MASK;
            carry = (carry >> DIGIT_BITS);
        }

        // Set output length
        sum.length = longArray.length;

        // Is there a carry into the next digit?
        if (carry !== 0) {
            sum[i] = carry & DIGIT_MASK;
        }

        return carry;
    }

    function subtract(minuend, subtrahend, difference) {
        /// <summary>Subtraction: difference = minuend - subtrahend. Condition: minuend.length &lt;= subtrahend.length.</summary>
        /// <param name="minuend" type="Array">Minuend.</param>
        /// <param name="subtrahend" type="Array">Subtrahend.</param>
        /// <param name="difference" type="Array">The difference.</param>
        /// <returns type="Number" integer="true">Returns -1 if there is a borrow (minuend &lt; subtrahend), or 0 if there isn't (minuend &gt;= subtrahend).</returns>

        var s = subtrahend.length;
        if (minuend.length < subtrahend.length) {
            s = mswIndex(subtrahend) + 1;
            if (minuend.length < s) {
                throw new Error("Subtrahend is longer than minuend, not supported.");
            }
        }
        var i, carry = 0;
        for (i = 0; i < s; i += 1) {
            carry += minuend[i] - subtrahend[i];
            difference[i] = carry & DIGIT_MASK;
            carry = carry >> DIGIT_BITS;
        }

        // Propagate the carry by subtracting from minuend into difference
        while (i < minuend.length) {
            carry += minuend[i];
            difference[i++] = carry & DIGIT_MASK;
            carry = carry >> DIGIT_BITS;
        }

        return carry;
    }

    function multiply(multiplicant, /* @dynamic */multiplier, product) {
        /// <summary>Multiply two arrays of digits into a third array using schoolbook.</summary>
        /// <param name="multiplicant" type="Array">Multiplicand.</param>
        /// <param name="multiplier">Multiplier.</param>
        /// <param name="product" type="Array">Product = multiplicant * multiplier.</param>
        /// <returns type="Array">The result buffer; same as the product argument.</returns>

        // Single number or an array?
        var mplr = (typeof multiplier === "number") ? [multiplier] : multiplier;
        var s = Math.max(multiplicant.length, mplr.length);
        var i, j, u;

        // P <- 0
        // We only have to do this for half of result
        //   since the upper half is over-written on the first i iteration.
        for (i = 0; i < s; i += 1) {
            product[i] = 0;
        }

        // For i from 0 by 1 to s - 1 do
        for (i = 0; i < mplr.length; i += 1) {

            // 'u <- 0'
            u = 0;

            // For j from 0 by 1 to s - 1 do
            for (j = 0; j < multiplicant.length; j += 1) {

                // '(u,v) <- a_j * b_i + p_(i+j) + u'
                u += multiplicant[j] * mplr[i] + product[i + j];

                // 'p_(i+j) <- v'
                product[i + j] = (u & DIGIT_MASK) /* v */;
                u = Math.floor(u / DIGIT_BASE); // 'v <- u, u <- 0'
            }

            product[multiplicant.length + i] = (u & DIGIT_MASK);
        }

        // set product length; there may still be leading zero digits after this
        product.length = multiplicant.length + mplr.length;

        return product;
    }

    function divRem(dividend, divisor, quotient, remainder, temp1, temp2) {
        /// <summary>Computes the quotient q and remainder r when dividend is divided by
        ///   divisor.</summary>
        /// <param name="dividend" type="Array">The dividend.</param>
        /// <param name="divisor" type="Array">The divisor.</param>
        /// <param name="quotient" type="Array">Receives the quotient (n digits).</param>
        /// <param name="remainder" type="Array">Receives the remainder (n digits).</param>
        /// <param name="temp1" type="Array" optional="true">Temporary storage (n digits).</param>
        /// <param name="temp2" type="Array" optional="true">Temporary storage (n digits).</param>
        /// <remarks>This is an implementation of Figure 9-1 is Knuth's Algorithm D [Knu2 sec. 4.3.1].
        /// Throws error on division by zero.
        /// </remarks>
        var m = mswIndex(dividend) + 1;        // zero-based length
        var n = mswIndex(divisor) + 1;        // zero-based length
        var qhat, rhat, carry, p, t, i, j;

        // Check for quick results and clear out conditionals
        if (m < n) {
            // dividend < divisor. q=0, remainder=dividend
            copyArray(dividend, 0, remainder, 0, dividend.length);
            remainder.length = dividend.length;
            normalizeDigitArray(remainder);
            quotient[0] = 0;
            quotient.length = 1;
            return;
        } else if (n === 0 || (n === 1 && divisor[n - 1] === 0)) { // self-explanatory
            throw new Error("Division by zero.");
        } else if (n === 1) {
            // divisor is single digit; do a simpler division
            t = divisor[0];
            rhat = 0;
            for (j = m - 1; j >= 0; j--) {
                p = (rhat * DIGIT_BASE) + dividend[j];
                quotient[j] = (p / t) & DIGIT_MASK;
                rhat = (p - quotient[j] * t) & DIGIT_MASK;
            }
            quotient.length = m;
            normalizeDigitArray(quotient);
            remainder[0] = rhat;
            remainder.length = 1;
            return;
        }

        // Normalization step. Align dividend and divisor so that their
        // most significant digits are at the same index.
        // Shift divisor by so many bits (0..DIGIT_BITS-1) to make MSB non-zero.
        var s = DIGIT_BITS - 1 - bitScanForward(divisor[n - 1]);
        var vn = temp1 || [];
        vn.length = n;
        shiftLeft(divisor, vn, s, n);

        var un = temp2 || [];
        un.length = m;
        shiftLeft(dividend, un, s, m);
        un[m] = un[m] || 0;     // must not be undefined

        // Main division loop with quotient estimate qhat
        quotient.length = m - n + 1;
        remainder.length = n;
        for (j = m - n; j >= 0; j--) {
            // Estimate quotient qhat using two-digit by one-digit division
            // because 3-digit by 2-digit division is more complex. Then, correct qhat after this.
            qhat = Math.floor((un[j + n] * DIGIT_BASE + un[j + n - 1]) / vn[n - 1]);
            rhat = (un[j + n] * DIGIT_BASE + un[j + n - 1]) - qhat * vn[n - 1];

            // If the quotient estimate is large, reduce the quotient estimate till the following is satisfied:
            //      qhat = {un[j+n, j+n-1, j+n-2]} div {uv[n-1,n-2]}
            while (true) {
                if (qhat >= DIGIT_BASE || (qhat * vn[n - 2]) > ((rhat * DIGIT_BASE) + un[j + n - 2])) {
                    qhat = qhat - 1;
                    rhat = rhat + vn[n - 1];
                    if (rhat < DIGIT_BASE) {
                        continue;
                    }
                }

                break;
            }

            // Multiply the [shifted] divisor by the quotient estimate and subtract the product from the dividend
            // un = un - qhat*vn
            carry = 0;
            for (i = 0; i < n; i++) {
                p = qhat * vn[i];
                t = un[i + j] - carry - (p & DIGIT_MASK);
                un[i + j] = t & DIGIT_MASK;
                //carry = (p >>> DIGIT_BITS) - (t >> DIGIT_BITS);
                // Don't shift: integer shifts are defined over 32-bit numbers in JS.
                carry = Math.floor(p / DIGIT_BASE) - Math.floor(t / DIGIT_BASE);
            }

            t = un[j + n] - carry;
            un[j + n] = t & DIGIT_MASK;

            // Store the estimated quotient digit (may need correction)
            quotient[j] = qhat & DIGIT_MASK;

            // Correction needed?
            if (t < 0) {
                // quotient too big (at most by 1 divisor)
                // decrement the quotient, and add [shifted] divisor back to the running dividend (remainder)
                quotient[j] = quotient[j] - 1;

                // un = un + vn
                carry = 0;
                for (i = 0; i < n; i++) {
                    t = un[i + j] + vn[i] + carry;
                    un[i + j] = t & DIGIT_MASK;
                    carry = t >> DIGIT_BITS;
                }
                un[j + n] = (un[j + n] + carry) & DIGIT_MASK;
            }
        }

        // De-normalize the remainder (shift right by s bits).
        for (i = 0; i < n; i++) {
            remainder[i] = ((un[i] >>> s) | (un[i + 1] << (DIGIT_BITS - s))) & DIGIT_MASK;
        }

        // Compute correct lengths for the quotient and remainder
        normalizeDigitArray(quotient);
        normalizeDigitArray(remainder);
    }

    function reduce(number, modulus, remainder, temp1, temp2) {
        /// <summary>Integer reduction by a modulus to compute number mod modulus. This function uses division,
        /// and should not be used for repetitive operations.</summary>
        /// <param name="number" type="Array">Input number to reduce.</param>
        /// <param name="modulus" type="Array">Modulus to reduce the input by.</param>
        /// <param name="remainder" type="Array">Output remainder = number mod modulus.</param>
        /// <param name="temp1" type="Array" optional="true">Temporary space, optional.</param>
        /// <param name="temp2" type="Array" optional="true">Temporary space, optional.</param>
        /// <returns type="Array">The resulting remainder is in 0..modulus-1; same as "remainder".</returns>

        // TODO: More efficient reduction implementation
        var quotient = [];
        divRem(number, modulus, quotient, remainder, temp1, temp2);

        return remainder;
    }

    function modMul(multiplicant, /*@dynamic*/multiplier, modulus, product, temp1, temp2) {
        /// <summary>Moduler multiplication of two numbers for a modulus. This function uses multiply and divide method,
        /// and should not be used for repetitive operations.
        /// product can be same as multiplicant and multiplier.</summary>
        /// <param name="multiplicant" type="Array">Multiplicand.</param>
        /// <param name="multiplier">Multiplier.</param>
        /// <param name="modulus" type="Array">Modulus to reduce the product.</param>
        /// <param name="product" type="Array">Output product = multiplicant * multiplier mod modulus.</param>
        /// <param name="temp1" type="Array" optional="true">Scratch space (optional).</param>
        /// <param name="temp2" type="Array" optional="true">Scratch space (optional).</param>
        /// <returns type="Array">The resulting product in in 0..modulus-1; same as product.</returns>

        var quotient = [];
        multiply(multiplicant, multiplier, quotient);
        divRem(quotient, modulus, quotient, product, temp1, temp2);

        return product;
    }

    function eea(a, b, upp, vpp, rpp) {
        /// <summary>Extended Euclidean Algorithm, Berlekamp's version. On return
        /// b*upp - a*vpp = (-1)(k-1)*rpp.</summary>
        /// <param name="a" type="Array">The first number a.</param>
        /// <param name="b" type="Array">The second number b.</param>
        /// <param name="upp" type="Array">a^-1 mod b if gcd=1. Optional.</param>
        /// <param name="vpp" type="Array">b^-1 mod a if gcd=1. Optional./</param>
        /// <param name="rpp" type="Array">gcd(a,b).</param>
        /// <returns type="Number">k value.</returns>
        /// <remarks>Algebraic Coding Theory, Pages 24-30.<code>
        ///     if k is odd
        ///         a*a^-1 = 1 mod b    ---> a^-1 = b - vpp
        ///         b*b^-1 = 1 mod a    ---> b^-1 = vpp
        ///     if k is even
        ///         a*a^-1 = 1 mod b    ---> a^-1 = upp
        ///         b*b^-1 = 1 mod a    ---> b^-1 = a - upp
        /// </code></remarks>
        // Initialize rpp and rp from two inputs a and b s.t. rpp >= rp
        var rp;     // initialized from a or b
        if (isZero(a)) {    // gcd = (0,b) = b
            copyArray(b, 0, rpp, 0, b.length);
            rpp.length = b.length;
            return 0;
        } else if (isZero(b)) {     // gcd = (a,0) = a
            copyArray(a, 0, rpp, 0, a.length);
            rpp.length = a.length;
            return 0;
        } else if (compareDigits(a, b) < 0) {
            rp = a.slice(0);
            copyArray(b, 0, rpp, 0, b.length); rpp.length = b.length;
        } else {
            rp = b.slice(0);
            copyArray(a, 0, rpp, 0, a.length); rpp.length = a.length;
        }

        normalizeDigitArray(rpp);
        normalizeDigitArray(rp);
        var q = new Array(rpp.length);
        var r = new Array(rpp.length);

        var v = new Array(rpp.length);
        var vppPresent = vpp !== undefined;
        var vp;
        if (vppPresent) {
            vp = new Array(rpp.length);
            vp[0] = 1; vp.length = 1;
            vpp[0] = 0; vpp.length = 1;
        }

        var up;
        var u = new Array(rpp.length);
        var uppPresent = upp !== undefined;
        if (uppPresent) {
            up = new Array(rpp.length);
            up[0] = 0; up.length = 1;
            upp[0] = 1; upp.length = 1;
        }

        // k starts at -1 so that on return, it is >=0.
        // In the following discussion, assume a<b and this is computing a^-1 mod b where (a,b)=1, a<b.
        // Initialize rp=a, rpp=b.
        // The integer k keeps track of the sign of a^-1 (0 = positive) in b = q*a + r with 0 = q*a + r mod b
        // such that for q=a^-1 and r=1 (which is gcd=1 for inverse to exist), we have q*a = (-1)^k mod b.
        // Thus, for odd k, q*a = -1 mod b, and a^-1 = b-q as in the description.
        var k = -1;

        // At the end, gcd = rp = (a,b)
        var upp_out = upp;
        var vpp_out = vpp;
        var rpp_out = rpp;
        var save;

        // Recycle u and v as temp variables in division (divRem).
        while (!isZero(rp)) {
            // rpp = q*rp + r: compute q, r
            divRem(rpp, rp, q, r, u, v);

            if (uppPresent) {
                // u = q*up + upp
                // upp=up, up=u, u=upp
                multiply(q, up, u);
                add(u, upp, u);
                normalizeDigitArray(u);
                save = upp;
                upp = up;
                up = u;
                u = save;
            }

            if (vppPresent) {
                // v = q*vp + vpp
                // vpp=vp, vp=v, v=vpp
                multiply(q, vp, v);
                add(v, vpp, v);
                normalizeDigitArray(v);
                save = vpp;
                vpp = vp;
                vp = v;
                v = save;
            }

            // rpp=rp, rp=r, r=rpp
            save = rpp;
            rpp = rp;
            rp = r;
            r = save;

            k++;
        }

        // copy to output upp, vpp, rpp
        if (uppPresent) {
            copyArray(upp, 0, upp_out, 0, upp.length); upp_out.length = upp.length;
        }
        if (vppPresent) {
            copyArray(vpp, 0, vpp_out, 0, vpp.length); vpp_out.length = vpp.length;
        }
        copyArray(rpp, 0, rpp_out, 0, rpp.length); rpp_out.length = rpp.length;

        return k;
    }

    function gcd(a, b, output) {
        /// <summary>Compute greatest common divisor or a and b.</summary>
        /// <param name="a" type="Array">First integer input.</param>
        /// <param name="b" type="Array">Second integer input.</param>
        /// <param name="output" type="Array" optional="true">GCD output (optional).</param>
        /// <returns type="Array">GCD(a,b), the same object as the output parameter if given or a new object otherwise.</returns>
        var aa = a;
        var bb = b;
        if (compareDigits(a, b) > 0) {
            aa = b;
            bb = a;
        }

        eea(aa, bb, undefined, undefined, output);
        return normalizeDigitArray(output);
    }

    function modInv(a, n, aInv, pad) {
        /// <summary>Modular multiplicative inverse a^-1 mod n.</summary>
        /// <param name="a" type="Array">The number to invert. Condition: a &lt; n, or the result would be n^-1 mod a.</param>
        /// <param name="n" type="Array">The modulus.</param>
        /// <param name="aInv" type="Array" optional="true">a^-1 mod n (optional).</param>
        /// <param name="pad" type="Boolean" optional="true">True to pad the returned value to the length of the modulus (optional).</param>
        /// <returns type="Array">a^-1 mod n. Same as the aInv parameter if the parameter is specified.</returns>
        //var gcd = eea(a, n, inv);
        var upp = new Array(n.length);
        var vpp = new Array(n.length);
        var rpp = new Array(n.length);
        var k = eea(a, n, vpp, upp, rpp);

        aInv = aInv || [];
        if (compareDigits(rpp, One) !== 0) {
            aInv[0] = NaN;
            aInv.length = 1;
        } else {
            // gcd = 1, there is an inverse.
            // Compute inverse from Berlekamp's EEA outputs.
            if ((k & 1) === 1) {
                subtract(n, upp, aInv);
            } else {
                copyArray(upp, 0, aInv, 0, upp.length); aInv.length = upp.length;
            }
            if (pad) {
                normalizeDigitArray(aInv, n.length, true);
            } else {
                normalizeDigitArray(aInv);
            }
        }

        return aInv;
    }

    function modExp(base, exponent, modulus, result) {
        /// <summary>Modular exponentiation in an integer group.</summary>
        /// <param name="base" type="Array">The base of the exponentiation.</param>
        /// <param name="exponent" type="Array">The exponent.</param>
        /// <param name="modulus" type="Array">Modulus to reduce the result.</param>
        /// <param name="result" type="Array" optional="true">Output element that takes the modular exponentiation result (optional).</param>
        /// <returns type="Array">Modular exponentiation result, same as <paramref name="result"/> if not null, or a new object.</returns>

        result = result || [];

        // If exponent is 0 return 1
        if (compareDigits(exponent, Zero) === 0) {
            result[0] = 1;
        } else if (compareDigits(exponent, One) === 0) {
            // If exponent is 1 return valueElement
            copyArray(base, 0, result, 0, base.length);
            result.length = base.length;
        } else {
            var montmul = new MontgomeryMultiplier(modulus);
            normalizeDigitArray(base, montmul.s, true);
            montmul.modExp(
                base,
                exponent,
                result);
            result.length = modulus.length;
        }

        return result;
    }

    function MontgomeryMultiplier(modulus) {
        /// <summary>Construct a new montgomeryMultiplier object with the given modulus.</summary>
        /// <param name="modulus" type="Array">A prime modulus in little-endian digit form</param>
        /// <remarks>Montgomery Multiplier class
        /// This class implements high performance montgomery multiplication using 
        /// CIOS, as well as modular exponentiation.</remarks>

        function computeM0Prime(m0) {
            /// <summary>Compute m' = -(m^-1) mod b, 16 bit digits. Based on Tolga Acar's code.</summary>
            /// <param name="m0" type="Number" integer="true">Digit m.</param>
            /// <returns type="Number">Digit m'.</returns>
            var m0Pr = 1;
            var a = 2;
            var b = 3;
            var c = b & m0;

            for (var i = 2; i <= DIGIT_BITS; i += 1) {
                if (a < c) {
                    m0Pr += a;
                }

                a = a << 1;
                b = (b << 1) | 1;
                c = m0 * m0Pr & b;
            }

            var result = (~m0Pr & DIGIT_MASK) + 1;
            return result;
        }

        function montgomeryMultiply(multiplicant, multiplier, result, ctx) {
            /// <summary>Montgomery multiplication with the CIOS method.</summary>
            /// <param name="multiplicant" type="Array">Multiplicant.</param>
            /// <param name="multiplier" type="Array">Multiplier.</param>
            /// <param name="result" type="Array">Computed result multiplicant * multiplier * r^-1 mod n.</param>
            /// <param name="ctx" type="MontgomeryMultiplier" optional="true">Context (optional = this).</param>

            ctx = ctx || this;

            // Upper digits of result
            var resultHigh = 0;

            // Precompute offsets
            var s = ctx.m.length;
            var sMinus1 = s - 1;

            // Local cache of m0, m', digitmask, digitbits
            var mPrime = ctx.mPrime;
            var m0 = ctx.m0;
            var left0 = multiplicant[0];

            var uv = 0, rightI, q, i, j, k;

            // Clear the result array
            for (i = 0; i < s; i += 1) {
                result[i] = 0;
            }

            for (i = 0; i < s; i += 1) {

                rightI = multiplier[i]; // Cache array value

                // 'u <- 0'

                // ---- UNROLL FIRST ITERATION (j == 0) ----
                uv = left0 * rightI + result[0];
                result[0] = uv & DIGIT_MASK;
                uv = Math.floor(uv / DIGIT_BASE);

                // ---- REMAINING ITERATIONS ----
                for (j = 1; j < s; j += 1) {

                    // '(u,v) <- a_j * b_i + z_j + u'
                    // uv = uv >>> DIGIT_BITS;
                    // Don't shift: JS supports shifts over 32-bit integers, only.
                    uv = multiplicant[j] * rightI + result[j] + uv;
                    result[j] = uv & DIGIT_MASK;
                    uv = Math.floor(uv / DIGIT_BASE);
                }
                // -------------------------------

                // '(u,v) <- z_s + u'.
                // 'z_s <- v'.
                // 'z_s+1 <- u'.
                resultHigh = resultHigh + uv;

                // 'q <- z_0 * m'  mod  digitBase
                q = (result[0] * mPrime) & DIGIT_MASK;

                // '(u,v) <- z_0 + m_0 * q'
                uv = Math.floor((result[0] + (m0 * q)) / DIGIT_BASE);

                // For j from 1 by 1 to s-1 
                for (j = 1, k = 0; j < s; j += 1, k++) {
                    // '(u,v) <- m_j * q + z_j + u'
                    uv = ctx.m[j] * q + result[j] + uv;

                    // 'z_j-1 <- v'
                    result[k] = uv & DIGIT_MASK;
                    uv = Math.floor(uv / DIGIT_BASE);
                }

                // '(u,v) <- z_s + u'.
                // 'z_s-1 <- v'.
                // 'z_s <- z_s+1 + u'.
                resultHigh += uv;
                result[sMinus1] = resultHigh & DIGIT_MASK;
                resultHigh = Math.floor(resultHigh / DIGIT_BASE);
            }

            // Subtract modulus

            // Make sure temp1 isn't also our passed-in result array.
            // This can happen if temp1 was returned as a result to a previous call.
            var resultMinusM = ctx.temp1 === result ? ctx.temp2 : ctx.temp1,
                carry = 0;

            for (i = 0; i < s; i += 1) {
                carry = result[i] - ctx.m[i] + (carry >> DIGIT_BITS);
                resultMinusM[i] = carry & DIGIT_MASK;
            }
            carry = (resultHigh & DIGIT_MASK) + (carry >> DIGIT_BITS);
            carry = (resultHigh >>> DIGIT_BITS) + (carry >> DIGIT_BITS);

            // Use carry as a mask to copy result into the return array
            for (i = 0; i < s; i += 1) {
                result[i] = (carry & (resultMinusM[i] ^ result[i])) ^ resultMinusM[i];
            }

            return;
        }

        function convertToMontgomeryForm(/*@type(Digits)*/digits) {
            /// <summary>Convert the digits in standard form to Montgomery residue representation.</summary>
            /// <param name="digits" type="Array">Input digits to convert, and also the output converted digits.</param>

            // Pad missing digits with zeroes
            if (digits.length < this.s) {
                digits.length = this.s;
                for (var i = 0; i < this.s; i++) {
                    digits[i] = isNaN(digits[i]) ? 0 : digits[i];
                }
            }

            var result = createArray(digits.length);

            this.montgomeryMultiply(digits, this.rSquaredModm, result);
            for (i = 0; i < this.s; i += 1) {
                digits[i] = result[i];
            }
        }

        function convertToStandardForm(digits) {
            /// <summary>Convert from Montgomery residue representation to the standard form.</summary>
            /// <param name="digits" type="Array">Input digits to convert, and also the output converted digits.</param>
            this.montgomeryMultiply(digits, this.one, this.temp1);
            for (var i = 0; i < this.s; i += 1) {
                digits[i] = this.temp1[i];
            }
        }

        function modExp(base, exponent, result) {
            /// <summary>Compute base to exponent mod m into result.</summary>
            /// <param name="base" type="Array">Base of length s in the context.</param>
            /// <param name="exponent" type="Array">Exponent.</param>
            /// <param name="result" type="Array">Output as base raised to exponent, and reduced to the modulus in the context.</param>
            /// <returns type="Array">result base^exponent mod m; the same result object.</returns>

            // Skip leading zero bits in the exponent
            // The total number of bits to scan in the exponent must be an integral multiple of
            // the number of bits to use in the exponent.
            var i;
            var expBitsToScan = 2;  // scan 2 bits at a time
            var expMask = DIGIT_MASK >>> (DIGIT_BITS - expBitsToScan);
            for (i = exponent.length - 1; i > 0 && exponent[i] === 0; i--) {
            }
            var bitsToScan = i * DIGIT_BITS + bitScanForward(exponent[i]) + 1;
            bitsToScan = bitsToScan + (expBitsToScan - (bitsToScan % expBitsToScan));
            var shiftAmt = (bitsToScan % DIGIT_BITS) - expBitsToScan;
            if (shiftAmt < 0) {
                shiftAmt += DIGIT_BITS;
            }
            var mask = expMask << shiftAmt;

            // Prepare the precomputation table of base for k bits
            // base[0..3] = [r, r*base, r*base^2, r*base^3] mod m
            for (i = 1; i < baseTable.length; i++) {
                modMul(baseTable[i - 1], base, this.m, baseTable[i], temp1, temp2);
                normalizeDigitArray(baseTable[i], this.s, true);
            }

            // a is the running result: a = 1*r mod m
            // TODO: Skip the first loop iteration below to avoid 1*1 mod m (minor optimization)
            var fourthPower = new Array(this.s);
            var squared = result;
            var partialResult = temp2;
            copyArray(this.rModM, 0, partialResult, 0, this.s);

            // Scan the exponent expBitsToScan bits at a time
            var tableIndex;
            while (bitsToScan > 0) {
                // result <- Mont(a, a);
                // result <- Mont(result, a);
                this.montgomeryMultiply(partialResult, partialResult, squared);
                this.montgomeryMultiply(squared, squared, fourthPower);

                // tableIndex <- the current bits of the scanned exponent
                tableIndex = (exponent[Math.floor((bitsToScan - 1) / DIGIT_BITS)] & mask) >>> shiftAmt;

                // aDigits = result * table[tableIndex]
                this.montgomeryMultiply(fourthPower, baseTable[tableIndex], partialResult);

                bitsToScan = bitsToScan - expBitsToScan;
                shiftAmt = shiftAmt - expBitsToScan;
                mask = mask >>> expBitsToScan;
                if (mask === 0) {
                    mask = expMask << (DIGIT_BITS - expBitsToScan);
                    shiftAmt = DIGIT_BITS - expBitsToScan;
                }
            }

            // result = Mont(a, 1)
            this.montgomeryMultiply(partialResult, this.one, result);
            return result;
        }

        // Modulus
        var m = modulus;

        // First digit of modulus
        var m0 = m[0];

        // Operand size (number of digits)
        var s = m.length;

        // The number one - used by modpow
        var one = createArray(s);
        one[0] = 1;

        // Compute m' = -(m^-1) mod b used by CIOS
        var mPrime = computeM0Prime(m0);

        // Create r and compute r mod m
        // Since we are base b integers of length s, we want
        // 'r = b^n = b^s'.
        var quotient = createArray(2 * s + 1);
        var rRemainder = createArray(s + 1);        // becomes rModM
        var temp1 = createArray(2 * s + 1);
        var temp2 = createArray(2 * s + 1);
        var rDigits = rRemainder;
        rDigits[s] = 1;
        divRem(
            rDigits,
            m,
            quotient,
            rRemainder,
            temp1,
            temp2);
        var rModM = normalizeDigitArray(rRemainder, s, true);

        // Compute R^2 mod m
        var rSquaredModm = createArray(2 * s + 1);
        var rSquaredDigits = rSquaredModm;
        rSquaredDigits[s * 2] = 1;
        divRem(
            rSquaredDigits,
            m,
            quotient,
            rSquaredModm,
            temp1,
            temp2);
        normalizeDigitArray(rSquaredModm, s, true);

        // Ready to do MontMul now - compute R^3
        var rCubedModm = createArray(s);
        var ctx = {
            m: m, mPrime: mPrime, m0: m0, temp1: temp1, temp2: temp2
        };
        montgomeryMultiply(
            rSquaredModm,
            rSquaredModm,
            rCubedModm,
            ctx);

        // Allocate space for multi-bit modular exponentiation
        var baseTable = new Array(4);
        baseTable[0] = rModM;
        baseTable[1] = new Array(s);
        baseTable[2] = new Array(s);
        baseTable[3] = new Array(s);

        // Return a per-instance context for Montgomery multiplier.
        // There is no need to use the "new" keyword when using this function.
        return {
            // Modulus
            m: modulus,

            // First digit of modulus
            m0: m0,

            // Compute m' = -(m^-1) mod b used by CIOS
            mPrime: mPrime,

            rSquaredModm: rSquaredModm,
            s: s,
            rModM: rModM,
            rCubedModm: rCubedModm,
            one: one,
            temp1: temp1,
            temp2: temp2,

            // Functions
            convertToMontgomeryForm: convertToMontgomeryForm,
            convertToStandardForm: convertToStandardForm,
            montgomeryMultiply: montgomeryMultiply,
            modExp: modExp
        };
    }

    function IntegerGroup(modulusBytes) {
        /// <summary>Construct a new IntegerGroup object with the given modulus.</summary>
        /// <param name="modulusBytes" type="Array">A big-endian number to represent the modulus in a byte array.</param>
        /// <remarks>This class represents the set of integers mod n. It is meant to be used in
        /// a variety of situations, for example to perform operations in the additive
        /// or multiplicative groups mod n. The modulus can be an arbitrary integer and
        /// in the case that it is a prime p then the integer group is the field Fp. The 
        /// user should be aware of what type of object the given modulus produces, and
        /// thus which operations are valid.</remarks>

        // Modulus
        var m_modulus = bytesToDigits(modulusBytes);

        // Length of an element in digits
        var m_digitWidth = m_modulus.length;

        // Setup numeric constants
        var m_zero = intToDigits(0, m_digitWidth);
        var m_one = intToDigits(1, m_digitWidth);

        // Temp storage.
        // Allocation in js is very slow, we use these temp arrays to avoid it.
        var temp0 = createArray(m_digitWidth);
        var temp1 = createArray(m_digitWidth);

        // Create montgomery multiplier object
        var montmul = new MontgomeryMultiplier(m_modulus);

        function createElementFromBytes(bytes) {
            /// <summary>Create a new element object from a byte value.</summary>
            /// <param name="bytes" type="Array">Desired element in big-endian format in an array of bytes.</param>
            /// <returns type="integerGroupElement">An element object representing the given element.</returns>            
            var digits = bytesToDigits(bytes);

            // Check size of the new element
            if (cryptoMath.compareDigits(digits, this.m_modulus) >= 0) {
                // Too many digits
                throw new Error("The number provided is not an element of this group");
            }

            // expand to the group modulus length
            normalizeDigitArray(digits, this.m_digitWidth, true);
            return integerGroupElement(digits, this);
        }

        function createElementFromInteger(integer) {
            /// <summary>Create a new element object from an integer value.</summary>
            /// <param name="integer" type="Number" integer="true">Desired element as an integer.</param>
            /// <returns type="integerGroupElement">An element object representing the given element.</returns>
            var digits = intToDigits(integer, this.m_digitWidth);
            return integerGroupElement(digits, this);
        }

        function createElementFromDigits(digits) {
            /// <summary>Create a new element object from a digit array.</summary>
            /// <param name="digits" type="Array">Desired element as a digit array.</param>
            /// <returns type="integerGroupElement">Object initialized with the given value.</returns>
            cryptoMath.normalizeDigitArray(digits, this.m_digitWidth, true);
            return integerGroupElement(digits, this);
        }

        function equals(otherGroup) {
            /// <summary>Return true if the given object is equivalent to this one.</summary>
            /// <param name="otherGroup" type="IntegerGroup"/>)
            /// <returns type="Boolean">True if the given objects are equivalent.</returns>

            return compareDigits(this.m_modulus, otherGroup.m_modulus) === 0;
        }

        function add(addend1, addend2, sum) {
            /// <summary>Add this element to another element.</summary>
            /// <param name="addend1" type="integerGroupElement"/>
            /// <param name="addend2" type="integerGroupElement"/>
            /// <param name="sum" type="integerGroupElement"/>

            var i;
            var s = this.m_digitWidth;
            var result = sum.m_digits;
            cryptoMath.add(addend1.m_digits, addend2.m_digits, result);
            var mask = compareDigits(result, this.m_modulus) >= 0 ? DIGIT_MASK : 0;

            // Conditional reduction by the modulus (one subtraction, only) only if the sum>modulus in almost constant time.
            // The result is unmodified if the computed sum < modulus already.
            var carry = 0;
            for (i = 0; i < s; i += 1) {
                carry = result[i] - (this.m_modulus[i] & mask) + carry;
                result[i] = carry & DIGIT_MASK;
                carry = (carry >> DIGIT_BITS);
            }

            result.length = s;
        }

        function subtract(leftElement, rightElement, outputElement) {
            /// <summary>Subtract an element from another element.</summary>
            /// <param name="leftElement" type="integerGroupElement"/>
            /// <param name="rightElement" type="integerGroupElement"/>
            /// <param name="outputElement" type="integerGroupElement"/>

            var i, s = this.m_digitWidth;
            var result = outputElement.m_digits;
            var carry = cryptoMath.subtract(leftElement.m_digits, rightElement.m_digits, outputElement.m_digits);

            // Final borrow?
            if (carry === -1) {
                carry = 0;
                for (i = 0; i < s; i += 1) {
                    carry += result[i] + this.m_modulus[i];
                    result[i] = carry & DIGIT_MASK;
                    carry = carry >> DIGIT_BITS;
                }
            }
        }

        function inverse(element, outputElement) {
            /// <summary>Compute the modular inverse of the given element.</summary>
            /// <param name="element" type="integerGroupElement">The element to be inverted.</param>
            /// <param name="outputElement" type="integerGroupElement">Receives the inverse element.</param>
            cryptoMath.modInv(element.m_digits, this.m_modulus, outputElement.m_digits);
        }

        function multiply(multiplicant, multiplier, product) {
            /// <summary>Multiply an element by another element in the integer group.</summary>
            /// <param name="multiplicant" type="integerGroupElement">Multiplicand.</param>
            /// <param name="multiplier" type="integerGroupElement">Multiplier.</param>
            /// <param name="product" type="integerGroupElement">Product reduced by the group modulus.</param>
            /// <returns type="Array">Same as <paramref name="product"/>.</returns>

            return cryptoMath.modMul(multiplicant.m_digits, multiplier.m_digits, this.m_modulus, product.m_digits, temp0, temp1);
        }

        function modexp(valueElement, exponent, outputElement) {
            /// <summary>Modular exponentiation in an integer group.</summary>
            /// <param name="valueElement" type="integerGroupElement">The base input to the exponentiation.</param>
            /// <param name="exponent" type="Array">The exponentas an unsigned integer.</param>
            /// <param name="outputElement" type="integerGroupElement" optional="true">Output element that takes the modular exponentiation result.</param>
            /// <returns type="integerGroupElement">Computed result. Same as <paramref name="outputElement"/> if not null, a new object otherwise.</returns>

            outputElement = outputElement || integerGroupElement([], this);

            // If exponent is 0 return 1
            if (compareDigits(exponent, m_zero) === 0) {
                outputElement.m_digits = intToDigits(1, this.m_digitWidth);
            } else if (compareDigits(exponent, m_one) === 0) {
                // If exponent is 1 return valueElement
                for (var i = 0; i < valueElement.m_digits.length; i++) {
                    outputElement.m_digits[i] = valueElement.m_digits[i];
                }
                outputElement.m_digits.length = valueElement.m_digits.length;
            } else {
                this.montmul.modExp(
                valueElement.m_digits,
        exponent,
        outputElement.m_digits);
                outputElement.m_digits.length = this.montmul.s;
            }

            return outputElement;
        }

        function integerGroupElement(digits, group) {
            /// <summary>integerGroupElement inner class.
            /// Create a new integer element mod n.
            /// </summary>
            /// <param name="digits" type="Array">
            /// An array of digits representing the element.
            /// </param>
            /// <param name="group" type="IntegerGroup">
            /// The parent group to which this element belongs.
            /// </param>

            // The value given in digits 
            // must be &gt;= 0 and &;lt; modulus. Note that the constructor should not be 
            // visible to the user, user should use group.createElementFromDigits(). This way we 
            // can use any digit size and endian-ness we wish internally, operating in
            // our chosen representation until such time as the user wishes to produce
            // a byte array as output, which will be done by calling 
            // toByteArrayUnsigned(). Note that other properties and methods are meant
            // to be "public" of course and thus callable by the user.

            return {
                // Variables
                m_digits: digits,
                m_group: group,

                // Functions
                equals: function (element) {
                    /// <summary>Compare an elements to this for equality.</summary>
                    /// <param name="element" type="integerGroupElement">Element to compare.</param>
                    /// <returns>True if elements are equal, false otherwise.</returns>
                    return (compareDigits(this.m_digits, element.m_digits) === 0) &&
                    this.m_group.equals(this.m_group, element.m_group);
                }
            };
        }

        return {
            // Variables
            m_modulus: m_modulus,
            m_digitWidth: m_digitWidth,
            montmul: montmul,

            // Functions
            createElementFromInteger: createElementFromInteger,
            createElementFromBytes: createElementFromBytes,
            createElementFromDigits: createElementFromDigits,
            equals: equals,
            add: add,
            subtract: subtract,
            multiply: multiply,
            inverse: inverse,
            modexp: modexp
        };
    }

    return {
        DIGIT_BITS: DIGIT_BITS,
        DIGIT_NUM_BYTES: DIGIT_NUM_BYTES,
        DIGIT_MASK: DIGIT_MASK,
        DIGIT_BASE: DIGIT_BASE,
        DIGIT_MAX: DIGIT_MAX,
        Zero: Zero,
        One: One,

        normalizeDigitArray: normalizeDigitArray,
        swapEndianness: swapEndianness,
        bytesToDigits: bytesToDigits,
        stringToDigits: stringToDigits,
        digitsToString: digitsToString,
        intToDigits: intToDigits,
        digitsToBytes: digitsToBytes,
        sequenceEqual: sequenceEqual,
        isZero: isZero,
        isEven: isEven,

        powerOfTwo: powerOfTwo,
        shiftRight: shiftRight,
        shiftLeft: shiftLeft,
        compareDigits: compareDigits,
        computeBitArray: computeBitArray,
        bitLength: highestSetBit,

        fixedWindowRecode: fixedWindowRecode,
        IntegerGroup: IntegerGroup,

        add: add,
        subtract: subtract,
        multiply: multiply,
        divRem: divRem,
        reduce: reduce,
        modInv: modInv,
        modExp: modExp,
        modMul: modMul,
        MontgomeryMultiplier: MontgomeryMultiplier,
        gcd: gcd
    };
}

var cryptoMath = cryptoMath || msrcryptoMath();
