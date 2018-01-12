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
var mathKATs = mathKATs || {};

module("cryptoMath-KAT");
mathKATs.testDescription = "Math KAT";

// These are in little endian, each array entry is a byte (unless it is DIGIT_MASK).
// byte to digit conversion is done below as needed.
mathKATs.dvd0 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness([14, 1]));
mathKATs.dvs0 = [128];
mathKATs.q0 = [2];
mathKATs.r0 = [14]; // dividend=270, divisor=128
mathKATs.dvd1 = [cryptoMath.DIGIT_MASK];
mathKATs.dvs1 = [1];
mathKATs.q1 = [cryptoMath.DIGIT_MASK];
mathKATs.r1 = [0];
mathKATs.dvd2 = [cryptoMath.DIGIT_MASK];
mathKATs.dvs2 = [2];
mathKATs.q2 = [cryptoMath.DIGIT_MASK >>> 1];
mathKATs.r2 = [1];
mathKATs.dvd3 = [cryptoMath.DIGIT_MASK >>> 2];
mathKATs.dvs3 = [2];
mathKATs.q3 = [cryptoMath.DIGIT_MASK >>> 3];
mathKATs.r3 = [1];
mathKATs.dvd4 = [0, cryptoMath.DIGIT_MASK];
mathKATs.dvs4 = [2];
mathKATs.q4 = [cryptoMath.DIGIT_BASE >>> 1, cryptoMath.DIGIT_MASK >>> 1];
mathKATs.r4 = [0];
mathKATs.dvd5 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK];
mathKATs.dvs5 = [1];
mathKATs.q5 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK];
mathKATs.r5 = [0];
mathKATs.dvd6 = [cryptoMath.DIGIT_MASK, 1];
mathKATs.dvs6 = [cryptoMath.DIGIT_MASK];
mathKATs.q6 = [2];
mathKATs.r6 = [1];
mathKATs.dvd7 = [0, 0, 0, 1];
mathKATs.dvs7 = [cryptoMath.DIGIT_MASK];
mathKATs.q7 = [1, 1, 1];
mathKATs.r7 = [1];
mathKATs.dvd8 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK];
mathKATs.dvs8 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK];
mathKATs.q8 = [1];
mathKATs.r8 = [0];
mathKATs.dvd9 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK];
mathKATs.dvs9 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK >>> (cryptoMath.DIGIT_BITS / 2)];
mathKATs.q9 = [cryptoMath.DIGIT_BASE >>> (cryptoMath.DIGIT_BITS / 2)];
mathKATs.r9 = [cryptoMath.DIGIT_MASK >>> (cryptoMath.DIGIT_BITS / 2)];
mathKATs.dvd10 = [cryptoMath.DIGIT_MASK, 0, cryptoMath.DIGIT_MASK];
mathKATs.dvs10 = [1, 0, 1];
mathKATs.q10 = [cryptoMath.DIGIT_MASK];
mathKATs.r10 = [0];
mathKATs.dvd11 = [cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK, cryptoMath.DIGIT_MASK];
mathKATs.dvs11 = [1, 0, 1];
mathKATs.q11 = [cryptoMath.DIGIT_MASK];
mathKATs.r11 = [0, cryptoMath.DIGIT_MASK];
mathKATs.dvd12b = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
mathKATs.dvs12b = [0x41, 0x33, 0x10, 0x75, 0x48, 0x3C, 0x3D, 0x85, 0x98, 0xE3, 0x37, 0xD0, 0xD4, 0xF1, 0xA9, 0x3D, 0x6C, 0x36, 0xED, 0x07, 0x87, 0xA6, 0x7A, 0xFD, 0xB2, 0xF8, 0x31, 0x64, 0x5C, 0x74, 0x98, 0xE0];
mathKATs.q12b = [0xC3, 0x5C, 0x94, 0x2D, 0xD4, 0x57, 0x97, 0xEA, 0xDD, 0xFC, 0x45, 0x2F, 0x82, 0x69, 0x41, 0xB4, 0xAA, 0x1A, 0x19, 0x59, 0x2D, 0x26, 0x22, 0x6, 0x44, 0x20, 0x29, 0xD4, 0x7, 0xBB, 0x3C, 0x12];
mathKATs.r12b = [0x7D, 0x99, 0xA9, 0xF3, 0x88, 0xFB, 0xC, 0xD2, 0xA2, 0x65, 0x24, 0x3B, 0x5F, 0xA8, 0xA5, 0xFE, 0x1B, 0xC7, 0xDD, 0x1B, 0x4F, 0x2, 0xFC, 0xF, 0xAF, 0x47, 0xC, 0xB8, 0x73, 0xA2, 0x89, 0xD];
mathKATs.dvd13b = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10];
mathKATs.dvs13b = [0x30, 0xCC, 0x45, 0xD9];
mathKATs.q13b = [0xC7, 0xA3, 0xC7, 0xCA, 0x6E, 0xD4, 0xCF, 0xAB, 0x1A, 0x7C, 0x61, 0xF1, 0xA0, 0x25, 0xB0, 0xD5, 0xB1, 0x5C, 0x40, 0xC5, 0x34, 0xF1, 0x71, 0xB2, 0x68, 0x9F, 0x62, 0x6E, 0x4C, 0xE9, 0xE4, 0xC4, 0x28, 0xC2, 0x5C, 0x86, 0x9C, 0x37, 0xC3, 0x8E, 0xB2, 0x1E, 0xA2, 0xBB, 0xBE, 0x3A, 0xB9, 0x14, 0x24, 0xAE, 0x3F, 0x39, 0x73, 0xB9, 0x18, 0x7E, 0x73, 0x15, 0xDA, 0x12];
mathKATs.r13b = [0xB0, 0xB6, 0x6B, 0x10];
mathKATs.dvd12 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.dvd12b));
mathKATs.dvs12 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.dvs12b));
mathKATs.q12 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.q12b));
mathKATs.r12 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.r12b));
mathKATs.dvd13 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.dvd13b));
mathKATs.dvs13 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.dvs13b));
mathKATs.q13 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.q13b));
mathKATs.r13 = cryptoMath.bytesToDigits(cryptoMath.swapEndianness(mathKATs.r13b));
mathKATs.dvd14 = cryptoMath.stringToDigits("26959946660873538059280334323183841250350249843923952699046031785985");
mathKATs.dvs14 = cryptoMath.stringToDigits("6277101735386680764176071790207833042079994389485051707391");
mathKATs.q14 = cryptoMath.stringToDigits("4294967294");
mathKATs.r14 = cryptoMath.stringToDigits("6277101733925179126845168872004148209382158113902828716031");

// dvd = dvs * q + r
mathKATs.kat = [
    { dvd: mathKATs.dvd14, dvs: mathKATs.dvs14, q: mathKATs.q14, r: mathKATs.r14 },
    { dvd: mathKATs.dvd13, dvs: mathKATs.dvs13, q: mathKATs.q13, r: mathKATs.r13 },
    { dvd: mathKATs.dvd12, dvs: mathKATs.dvs12, q: mathKATs.q12, r: mathKATs.r12 },
    { dvd: mathKATs.dvd0, dvs: mathKATs.dvs0, q: mathKATs.q0, r: mathKATs.r0 },
    { dvd: mathKATs.dvd1, dvs: mathKATs.dvs1, q: mathKATs.q1, r: mathKATs.r1 },
    { dvd: mathKATs.dvd2, dvs: mathKATs.dvs2, q: mathKATs.q2, r: mathKATs.r2 },
    { dvd: mathKATs.dvd3, dvs: mathKATs.dvs3, q: mathKATs.q3, r: mathKATs.r3 },
    { dvd: mathKATs.dvd4, dvs: mathKATs.dvs4, q: mathKATs.q4, r: mathKATs.r4 },
    { dvd: mathKATs.dvd5, dvs: mathKATs.dvs5, q: mathKATs.q5, r: mathKATs.r5 },
    { dvd: mathKATs.dvd6, dvs: mathKATs.dvs6, q: mathKATs.q6, r: mathKATs.r6 },
    { dvd: mathKATs.dvd7, dvs: mathKATs.dvs7, q: mathKATs.q7, r: mathKATs.r7 },
    { dvd: mathKATs.dvd8, dvs: mathKATs.dvs8, q: mathKATs.q8, r: mathKATs.r8 },
    { dvd: mathKATs.dvd9, dvs: mathKATs.dvs9, q: mathKATs.q9, r: mathKATs.r9 },
    { dvd: mathKATs.dvd10, dvs: mathKATs.dvs10, q: mathKATs.q10, r: mathKATs.r10 },
    { dvd: mathKATs.dvd11, dvs: mathKATs.dvs11, q: mathKATs.q11, r: mathKATs.r11 },
    { dvd: [1], dvs: [1], q: [1], r: [0] },
    { dvd: [2], dvs: [1], q: [2], r: [0] },
    { dvd: [17], dvs: [2], q: [8], r: [1] },
    { dvd: [130], dvs: [32], q: [4], r: [2] }
];

// Computations are done in Maple for ModExp tests
// Modular exponentiation KAT vectors
mathKATs.p256 = cryptoMath.stringToDigits("115792089210356248762697446949407573530086143415290314195533631308867097853951");
//mathKATs.p254 = cryptoMath.stringToDigits("16798108731015832284940804142231733909889187121439069848933715426072753864723");
mathKATs.a = cryptoMath.stringToDigits("104511168451881842412851576755596659700315221718273942328869867798110481697158");
mathKATs.a_p2 = cryptoMath.stringToDigits("67809299381367188524822819136146927790962787213644606239163119442817673905237");
mathKATs.a_p4 = cryptoMath.stringToDigits("87894546340083992926263792938198975728059313974864761934362139870041025238461");
mathKATs.a_pMed1 = cryptoMath.stringToDigits("31236558755483442140787662568603962839154060947138071212092929305820568621386");
mathKATs.a_pMed2 = cryptoMath.stringToDigits("12042318358689110179565930040358062822158601509693937763088793686516115528750");
mathKATs.a_pMed = cryptoMath.stringToDigits("81209502525171891903707703217447831711876771640845643440693491933812807376347");
mathKATs.e1 = cryptoMath.stringToDigits("7414162892465213334030828303412235560821473691071505187272520222360884800572");
mathKATs.e2 = cryptoMath.stringToDigits("1360240116723035090984662812996037273826170337316186823827334098463450987952");
mathKATs.eMed1 = cryptoMath.stringToDigits("1234567890");
mathKATs.eMed2 = cryptoMath.stringToDigits("7894561239");
mathKATs.ca = cryptoMath.stringToDigits("5556461048081165493587167906401055717678447318153944555976620752872087463219");
mathKATs.c1 = cryptoMath.stringToDigits("35890007090844955553878902499519022264859643257042431954224772843700779292661");
mathKATs.c2 = cryptoMath.stringToDigits("28043628949882475330403586451346803983510326305651858350693910856769544580517");

// modular addition KAT vectors
mathKATs.sum_a_a = cryptoMath.stringToDigits("93230247693407436063005706561785745870544300021257570462206104287353865540365");
mathKATs.sum_e1_e2 = cryptoMath.stringToDigits("8774403009188248425015491116408272834647644028387692011099854320824335788524");
mathKATs.sum_a_e2 = cryptoMath.stringToDigits("105871408568604877503836239568592696974141392055590129152697201896573932685110");

// ModExp. From Maple
mathKATs.modexp_base1 = cryptoMath.stringToDigits("3202505803019b91360ef7711602337a0cbb8fcae05466e0ec16da3946481c5b4e4db489124e6dbdd4fc23ce42fb00c1", 16);
mathKATs.modexp_e1 = cryptoMath.stringToDigits("7bfc5320e2e8a18ed6eb87652cdda2c325a3a664ae6f0bb2220662619b6632b1f962a03780c94a1032b9acf4e237eb18", 16);
mathKATs.modexp_modulus1 = cryptoMath.stringToDigits("90594b919a6d16c15ec79d7eacf0d9e4a74374abe090a94f1ddff2c1be8055bbfafd9cb59553e45aa6f3e27bdd96a06b", 16);
mathKATs.modexp_result1 = cryptoMath.stringToDigits("D250A4F7D68FA93C1F2C9FF68BC0EBDDE202087E434766601F6D9029A9C7D49237762F22D87F122EB79C3AA270DF2FE", 16);

// c1=a^e1, c2=a^e2, ca=c1*c2 mod n
mathKATs.ModExpKAT = [
    { a: mathKATs.modexp_base1, e1: mathKATs.modexp_e1, e2: [0], c1: mathKATs.modexp_result1, c2: [1], ca: mathKATs.modexp_result1, n: mathKATs.modexp_modulus1 },
    { a: [1], e1: [1], e2: [1], c1: [1], c2: [1], ca: [1], n: mathKATs.p256 },
    { a: [1], e1: [1], e2: [1], c1: [1], c2: [1], ca: [1], n: [67] },
    { a: [2], e1: [2], e2: [3], c1: [4], c2: [8], ca: [32], n: [67] },
    { a: mathKATs.a, e1: mathKATs.e1, e2: mathKATs.e2, c1: mathKATs.c1, c2: mathKATs.c2, ca: mathKATs.ca, n: mathKATs.p256 },
    { a: mathKATs.a, e1: [1], e2: [1], c1: mathKATs.a, c2: mathKATs.a, ca: mathKATs.a_p2, n: mathKATs.p256 },
    { a: mathKATs.a, e1: [2], e2: [2], c1: mathKATs.a_p2, c2: mathKATs.a_p2, ca: mathKATs.a_p4, n: mathKATs.p256 },
    { a: mathKATs.a, e1: mathKATs.eMed1, e2: mathKATs.eMed2, c1: mathKATs.a_pMed1, c2: mathKATs.a_pMed2, ca: mathKATs.a_pMed, n: mathKATs.p256 }
];

// s = a1 + a2 mod n
mathKATs.ModAddKAT = [
    { a1: [0], a2: [0], s: [0], n: [5] },
    { a1: [0], a2: [0], s: [0], n: [5] },
    { a1: [1], a2: [4], s: [0], n: [5] },
    { a1: [cryptoMath.DIGIT_MAX - 1], a2: [1], s: [0], n: [cryptoMath.DIGIT_MAX] },
    { a1: [1], a2: [cryptoMath.DIGIT_MAX - 1], s: [0], n: [cryptoMath.DIGIT_MAX] },
    { a1: [cryptoMath.DIGIT_MAX - 2], a2: [cryptoMath.DIGIT_MAX - 1], s: [cryptoMath.DIGIT_MAX - 3], n: [cryptoMath.DIGIT_MAX] },
    { a1: [cryptoMath.DIGIT_MAX - 1], a2: [cryptoMath.DIGIT_MAX - 1], s: [cryptoMath.DIGIT_MAX - 2], n: [cryptoMath.DIGIT_MAX] },
    { a1: mathKATs.a, a2: mathKATs.a, s: mathKATs.sum_a_a, n: mathKATs.p256 },
    { a1: mathKATs.e1, a2: mathKATs.e2, s: mathKATs.sum_e1_e2, n: mathKATs.p256 },
    { a1: mathKATs.a, a2: mathKATs.e2, s: mathKATs.sum_a_e2, n: mathKATs.p256 }
];

// fill the division table with powers of 2
mathKATs.divTable = [];
for (var i = 0; i < 32; ++i) {
    mathKATs.divTable.push(Math.pow(2, i));
}


mathKATs.StringDigitConversion = function (radix) {
    for (var i = 0; i < mathKATs.kat.length; ++i) {
        var divisor = mathKATs.kat[i].dvs.slice(0);
        var quotient = mathKATs.kat[i].q.slice(0);
        var remainder = mathKATs.kat[i].r.slice(0);
        var dividend = mathKATs.kat[i].dvd.slice(0);

        // Convert to string, and then back.
        var dvd_b = cryptoMath.digitsToString(dividend, radix);
        var dvs_b = cryptoMath.digitsToString(divisor, radix);
        var q_b = cryptoMath.digitsToString(quotient, radix);
        var r_b = cryptoMath.digitsToString(remainder, radix);

        var dvd = cryptoMath.stringToDigits(dvd_b, radix);
        var dvs = cryptoMath.stringToDigits(dvs_b, radix);
        var q = cryptoMath.stringToDigits(q_b, radix);
        var r = cryptoMath.stringToDigits(r_b, radix);

        // Verify the results
        var pass = cryptoMath.compareDigits(remainder, r) === 0 &&
            cryptoMath.compareDigits(quotient, q) === 0 &&
            cryptoMath.compareDigits(dividend, dvd) === 0 &&
            cryptoMath.compareDigits(divisor, dvs) === 0;
        ok(pass, "String/Digit convertion test " + pass.toString() + " - [" + i.toString() + "]:" +
            "dividend=" + dividend.toString() + "\n" +
            "dvd=" + dvd.toString() + "\n" +
            "divisor=" + divisor.toString() + "\n" +
            "dvs=" + dvs.toString() + "\n" +
            "remainder=" + remainder.toString() + "\n" +
            "r=" + r.toString() + "\n" +
            "quotient=" + quotient.toString() + "\n" +
            "q=" + q.toString()
            );
    }
};

test("Digit/Byte Conversion", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    for (var i = 0; i < mathKATs.kat.length; ++i) {
        var divisor = mathKATs.kat[i].dvs.slice(0);
        var quotient = mathKATs.kat[i].q.slice(0);
        var remainder = mathKATs.kat[i].r.slice(0);
        var dividend = mathKATs.kat[i].dvd.slice(0);

        // Convert to bytes, and then back.
        var dvd_b = cryptoMath.digitsToBytes(dividend);
        var dvs_b = cryptoMath.digitsToBytes(divisor);
        var q_b = cryptoMath.digitsToBytes(quotient);
        var r_b = cryptoMath.digitsToBytes(remainder);

        var dvd = cryptoMath.bytesToDigits(dvd_b);
        var dvs = cryptoMath.bytesToDigits(dvs_b);
        var q = cryptoMath.bytesToDigits(q_b);
        var r = cryptoMath.bytesToDigits(r_b);

        // Verify the results
        var pass = cryptoMath.compareDigits(remainder, r) === 0 &&
            cryptoMath.compareDigits(quotient, q) === 0 &&
            cryptoMath.compareDigits(dividend, dvd) === 0 &&
            cryptoMath.compareDigits(divisor, dvs) === 0;
        ok(pass, "Byte/Digit convertion test " + pass.toString() + " - [" + i.toString() + "]:" +
            "dividend=" + dividend.toString() + "\n" +
            "dvd=" + dvd.toString() + "\n" +
            "divisor=" + divisor.toString() + "\n" +
            "dvs=" + dvs.toString() + "\n" +
            "remainder=" + remainder.toString() + "\n" +
            "r=" + r.toString() + "\n" +
            "quotient=" + quotient.toString() + "\n" +
            "q=" + q.toString()
            );
    }
});

test("String/Digit Conversion, base 10", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);      // * number of radices below.

    // Radix 10
    mathKATs.StringDigitConversion(10);
});

test("String/Digit Conversion, base 16", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    // Radix 16
    mathKATs.StringDigitConversion(16);
});

test("String/Digit Conversion, base 29", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    // Radix 29
    mathKATs.StringDigitConversion(29);
});

test("Integer to Digits", function () {
    var numberOfTests = cryptoMath.DIGIT_BITS;
    expect(4 * numberOfTests);

    for (var i = 0; i < numberOfTests; ++i) {
        var d1 = cryptoMath.intToDigits(i);
        var d2 = cryptoMath.intToDigits(i, 8);
        equal(d1[0], i, "Integer to digit conversion passed ");
        equal(d2[0], i, "Integer to digit conversion passed, length=" + d2.length);

        var j = i + cryptoMath.DIGIT_BASE;
        d1 = cryptoMath.intToDigits(j);
        d2 = cryptoMath.intToDigits(j, 8);
        equal(d1[0] + d1[1] * cryptoMath.DIGIT_BASE, j, "Integer to digit conversion passed ");
        equal(d2[0] + d2[1] * cryptoMath.DIGIT_BASE, j, "Integer to digit conversion passed , length=" + d2.length);
    }
});

test("Division", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    for (var i = 0; i < mathKATs.kat.length; ++i) {
        var dividend = mathKATs.kat[i].dvd.slice(0);
        var divisor = mathKATs.kat[i].dvs.slice(0);
        var actualQuotient = mathKATs.kat[i].q.slice(0);
        var actualRemainder = mathKATs.kat[i].r.slice(0);
        var quotient = [0];
        var remainder = [0];

        cryptoMath.divRem(dividend, divisor, quotient, remainder);

        // Verify the results
        var pass = cryptoMath.compareDigits(actualQuotient, quotient) === 0 &&
            cryptoMath.compareDigits(actualRemainder, remainder) === 0;
        ok(pass, "Division test " + pass.toString() + " - [" + i.toString() + "]:" +
            "dividend=" + dividend.toString() + "\n" +
            "divisor=" + divisor.toString() + "\n" +
            "quotient=" + quotient.toString() + "\n" +
            "remainder=" + remainder.toString() + "\n" +
            "actualQuotient=" + actualQuotient.toString() + "\n" +
            "actualRemainder=" + actualRemainder.toString());
    }
});

test("Subtract", function () {
    var kat = [
        // (c,s) = a + b with c as the carry not captured in s.
        { a: [1], b: [1], s: [2], c:[0] },
        { a: "12345678901234567890123456789012345", b: [1], s: "12345678901234567890123456789012346", c: [0] },
        { a: "12345678901234567890123456789012345", b: [0], s: "12345678901234567890123456789012345", c: [0] },
        { a: [cryptoMath.DIGIT_MASK], b: [0], s: [cryptoMath.DIGIT_MASK], c: [0] },
        { a: [cryptoMath.DIGIT_MASK], b: [10], s: [9], c: [1] }
    ];

    var numberOfTests = kat.length;
    expect(numberOfTests);

    var carry, pass;
    var v1 = [], v2 = [], v3 = [];
    for (var i = 0; i < kat.length; ++i) {
        var a = typeof (kat[i].a) === "string" ? cryptoMath.stringToDigits(kat[i].a) : kat[i].a;
        var b = typeof (kat[i].b) === "string" ? cryptoMath.stringToDigits(kat[i].b) : kat[i].b;
        var s = typeof (kat[i].s) === "string" ? cryptoMath.stringToDigits(kat[i].s) : kat[i].s;
        var c = typeof (kat[i].c) === "string" ? cryptoMath.stringToDigits(kat[i].c) : kat[i].c;

        v1.length = v2.length = v3.length = 0;
        // a + b
        cryptoMath.add(a, b, v1);
        v2 = s.slice(0);
        v2[v2.length] = c[0];
        pass = cryptoMath.compareDigits(v2, v1) === 0;

        // s - a
        v2.length = 0;
        carry = cryptoMath.subtract(s, a, v2) !== 0 ? 1 : 0;
        pass = pass && (cryptoMath.compareDigits(b, v2) === 0) && (carry === c[0]);

        // s - b
        carry = cryptoMath.subtract(s, b, v3) !== 0 ? 1 : 0;
        pass = pass && (cryptoMath.compareDigits(a, v3) === 0) && (carry === c[0]);

        ok(pass, "Add & subtract test [" + i.toString() + "]:" +
            "a=" + a.toString() + "\n" +
            "b=" + b.toString() + "\n" +
            "s=" + s.toString() + "\n" +
            "c=" + c.toString() + "\n" +
            "a+b=" + v1.toString() + "\n" +
            "s-a=" + v2.toString() + "\n" +
            "s-b=" + v3.toString() + "\n"
            );
    }
});

test("Multiply & Add", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    for (var i = 0; i < mathKATs.kat.length; ++i) {
        var multiplicant = mathKATs.kat[i].dvs.slice(0);
        var multiplier = mathKATs.kat[i].q.slice(0);
        var remainder = mathKATs.kat[i].r.slice(0);
        var actualProduct = mathKATs.kat[i].dvd.slice(0);
        var product = [0];

        // quotient * divisor + remainder = dividend
        cryptoMath.multiply(multiplicant, multiplier, product);
        cryptoMath.add(product, remainder, product);
        cryptoMath.normalizeDigitArray(product);

        // Verify the results
        var pass = cryptoMath.compareDigits(actualProduct, product) === 0;

        ok(pass, "Multiplication & addition test " + pass.toString() + " - [" + i.toString() + "]:" +
            "multiplicant=" + multiplicant.toString() + "\n" +
            "multiplier=" + multiplier.toString() + "\n" +
            "product=" + product.toString() + "\n" +
            "actualProduct=" + actualProduct.toString());
    }
});

test("Add & Double", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    var n1 = [], n2 = [], n3 = [], n4 = [];
    var n5 = [], n6 = [], n7 = [], n8 = [];
    var two = cryptoMath.intToDigits(2);
    var carry;
    for (var i = 0; i < mathKATs.kat.length; ++i) {
        var divisor = mathKATs.kat[i].dvs;
        var dividend = mathKATs.kat[i].dvd;
        var quotient = mathKATs.kat[i].q;
        var remainder = mathKATs.kat[i].r;

        // n1 = dividend + dividend
        // n2 = 2 * dividend
        cryptoMath.add(dividend, dividend, n1);
        cryptoMath.multiply(dividend, two, n2);

        // n3 = divisor + divisor
        // n4 = 2 * divisor
        cryptoMath.add(divisor, divisor, n3);
        cryptoMath.multiply(divisor, two, n4);

        // n5 = quotient + quotient
        // n6 = 2 * quotient
        cryptoMath.add(quotient, quotient, n5);
        cryptoMath.multiply(quotient, two, n6);

        // n7 = remainder * remainder
        // n8 = 2 * remainder
        cryptoMath.add(remainder, remainder, n7);
        cryptoMath.multiply(remainder, two, n8);

        // Verify the results
        var pass = (cryptoMath.compareDigits(n1, n2) === 0) &&
            (cryptoMath.compareDigits(n3, n4) === 0) &&
            (cryptoMath.compareDigits(n5, n6) === 0) &&
            (cryptoMath.compareDigits(n7, n8) === 0);
        ok(pass, "Add & double test " + pass.toString() + " - [" + i.toString() + "]:" +
            "dividend=" + dividend.toString() + "\n" +
            "divisor=" + divisor.toString() + "\n" +
            "n1=" + n1.toString() + "\n" +
            "n2=" + n2.toString() + "\n" +
            "n3=" + n3.toString() + "\n" +
            "n4=" + n4.toString() + "\n" +
            "n5=" + n5.toString() + "\n" +
            "n6=" + n6.toString() + "\n" +
            "n7=" + n7.toString() + "\n" +
            "n8=" + n8.toString()
            );
    }
});

test("Multiply & Subtract", function () {
    var numberOfTests = mathKATs.kat.length;
    expect(numberOfTests);

    for (var i = 0; i < mathKATs.kat.length; ++i) {
        var multiplicant = mathKATs.kat[i].dvs.slice(0);
        var multiplier = mathKATs.kat[i].q.slice(0);
        var actualRemainder = mathKATs.kat[i].r.slice(0);
        var actualProduct = mathKATs.kat[i].dvd.slice(0);
        var product = [0];
        var remainder = [0];

        // remainder = product - multiplicant * multiplier
        cryptoMath.multiply(multiplicant, multiplier, product);
        cryptoMath.normalizeDigitArray(product);
        cryptoMath.subtract(actualProduct, product, remainder);

        // Verify the results
        var pass = cryptoMath.compareDigits(actualRemainder, remainder) === 0;

        ok(pass, "Multiplication & subtraction test " + pass.toString() + " - [" + i.toString() + "]:" +
            "multiplicant=" + multiplicant.toString() + "\n" +
            "multiplier=" + multiplier.toString() + "\n" +
            "remainder=" + remainder.toString() + "\n" +
            "actualRemainder=" + actualRemainder.toString());
    }
});

test("GCD", function () {
    // Numbers computed and verified in Maple.
    var kat = [
        { a: [1], b: [1], g: [1] },
        { a: [5], b: [0], g: [5] },
        { a: [0], b: [14], g: [14] },
        { a: [125], b: [5], g: [5] },
        { a: [25], b: [25], g: [25] },
        { a: "123456789", b: "123456789", g: "123456789" },
        { a: "947112345600034501049650912347895", b: "5", g: "5" },
        { a: mathKATs.p256, b: "123456789", g: [1] },
        { a: [5], b: [9], g: [1] },
        { a: [7], b: [21], g: [7] },
        { a: [4], b: [32], g: [4] },
        { a: [4], b: "39916801", g: [1] },
        { a: "305588104335913948", b: "296420461205836529560", g: "305588104335913948" },
        { a: "57628118731781590099588725298442097356713567422233718737810811350517835423023", b: "115792089210356248762697446949407573530086143415290314195533631308867097853951", g: "1" },
        { a: "26959946660873538059280334323183841250350249843923952699046031785985", b: "115792089183396302114378112356516095823261736990586219612555396166510339686400", g: "5" }
    ];
    expect(kat.length);
    for (var i = 0; i < kat.length; ++i) {
        var g = [];
        if (typeof (kat[i].a) === "string") {
            kat[i].a = cryptoMath.stringToDigits(kat[i].a);
        }
        if (typeof (kat[i].b) === "string") {
            kat[i].b = cryptoMath.stringToDigits(kat[i].b);
        }
        if (typeof (kat[i].g) === "string") {
            kat[i].g = cryptoMath.stringToDigits(kat[i].g);
        }
        cryptoMath.gcd(kat[i].a, kat[i].b, g);
        var passed = (cryptoMath.compareDigits(g, kat[i].g) === 0);
        ok(passed, "GCD[" + i.toString() + "]");
    }
});

test("ModExp", function () {
    // c1 = a ^ e1 mod n
    // c2 = a ^ e2 mod n
    // c3 = a ^ (e1+e2) mod n
    // c4 = c1*c2 mod n
    // c3 ?== c4
    var numberOfTests = mathKATs.ModExpKAT.length;
    expect(numberOfTests);

    var cc1 = [];
    var cc2 = [];
    var cca = [];
    var c1mc2 = [];
    for (var i = 0; i < numberOfTests; ++i) {
        var e1pe2 = [], q = [], r = [];

        var modulus = mathKATs.ModExpKAT[i].n;
        var a = cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].a, modulus.length, true);
        var e1 = cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].e1, modulus.length, true);
        var e2 = cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].e2, modulus.length, true);
        var c1 = mathKATs.ModExpKAT[i].c1;
        var c2 = mathKATs.ModExpKAT[i].c2;
        var ca = mathKATs.ModExpKAT[i].ca;

        // e1pe2 = e1 + e2  (do not reduce by \phi(p))
        cryptoMath.add(e1, e2, e1pe2);

        // cc1 = a^e1 mod p
        // cc2 = a^e2 mod p
        // cca = a^(e1+e2) mod p
        // c1mc2 = cc1*cc2 mod p
        cryptoMath.modExp(a, e1, modulus, cc1);
        cryptoMath.modExp(a, e2, modulus, cc2);
        cryptoMath.modExp(a, e1pe2, modulus, cca);
        cryptoMath.modMul(cc1, cc2, modulus, c1mc2);

        // Verify the results
        var pass = (cryptoMath.compareDigits(cca, c1mc2) === 0) &&
            (cryptoMath.compareDigits(cc1, c1) === 0) &&
            (cryptoMath.compareDigits(cc2, c2) === 0) &&
            (cryptoMath.compareDigits(cca, ca) === 0);

        ok(pass, "ModExp test. " +
            "c1=" + c1.toString() + "\n" +
            "c2=" + c2.toString() + "\n" +
            "ca=" + ca.toString() + "\n" +
            "cc1=" + cc1.toString() + "\n" +
            "cc2=" + cc2.toString() + "\n" +
            "cca=" + cca.toString()
            );
    }
});

test("IntegerGroup.ModExp", function () {
    // c1 = a ^ e1 mod n
    // c2 = a ^ e2 mod n
    // c3 = a ^ (e1+e2) mod n
    // c4 = c1*c2 mod n
    // c3 ?== c4
    var numberOfTests = mathKATs.ModExpKAT.length;
    expect(numberOfTests);

    for (var i = 0; i < numberOfTests; ++i) {
        var e1pe2 = [], q = [], r = [];
        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(mathKATs.ModExpKAT[i].n));
        var cc1 = group.createElementFromInteger(0);
        var cc2 = group.createElementFromInteger(0);
        var cca = group.createElementFromInteger(0);
        var c1mc2 = group.createElementFromInteger(0);

        cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].a, group.m_digitWidth, true);
        cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].e1, group.m_digitWidth, true);
        cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].e2, group.m_digitWidth, true);

        var a = group.createElementFromDigits(mathKATs.ModExpKAT[i].a);
        var e1 = mathKATs.ModExpKAT[i].e1;
        var e2 = mathKATs.ModExpKAT[i].e2;
        var c1 = group.createElementFromDigits(mathKATs.ModExpKAT[i].c1);
        var c2 = group.createElementFromDigits(mathKATs.ModExpKAT[i].c2);
        var ca = group.createElementFromDigits(mathKATs.ModExpKAT[i].ca);

        // e1pe2 = e1 + e2  (do not reduce by \phi(p))
        cryptoMath.add(e1, e2, e1pe2);

        // cc1 = a^e1 mod p
        // cc2 = a^e2 mod p
        // cca = a^(e1+e2) mod p
        // c1mc2 = cc1*cc2 mod p
        group.modexp(a, e1, cc1);
        group.modexp(a, e2, cc2);
        group.modexp(a, e1pe2, cca);
        group.multiply(cc1, cc2, c1mc2);
        cryptoMath.normalizeDigitArray(cc1.m_digits);
        cryptoMath.normalizeDigitArray(cc2.m_digits);
        cryptoMath.normalizeDigitArray(cca.m_digits);
        cryptoMath.normalizeDigitArray(c1mc2.m_digits);

        // Verify the results
        var pass = (cca.equals(c1mc2)) &&
            (cc1.equals(c1)) &&
            (cc2.equals(c2)) &&
            (cca.equals(ca));

        ok(pass, "ModExp test. " +
            "c1=" + c1.toString() + "\n" +
            "c2=" + c2.toString() + "\n" +
            "ca=" + ca.toString() + "\n" +
            "cc1=" + cc1.toString() + "\n" +
            "cc2=" + cc2.toString() + "\n" +
            "cca=" + cca.toString()
            );
    }
});

test("IntegerGroup Multiplicative Inversion", function () {
    // c1 = a ^ -1 mod p
    // c2 = a ^ (p-2) mod p
    // c2 ?== c1
    // a * c1 ?== 1 mod p
    var numberOfTests = mathKATs.ModExpKAT.length;
    expect(numberOfTests);

    for (var i = 0; i < numberOfTests; ++i) {
        var pm2 = [];
        var two = [2];
        var one = [1];
        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(mathKATs.ModExpKAT[i].n));
        cryptoMath.normalizeDigitArray(one, group.m_digitWidth, true);
        cryptoMath.normalizeDigitArray(two, group.m_digitWidth, true);
        cryptoMath.subtract(group.m_modulus, two, pm2);
        var c1 = group.createElementFromInteger(0);
        var c2 = group.createElementFromInteger(0);
        var c3 = group.createElementFromInteger(0);

        cryptoMath.normalizeDigitArray(mathKATs.ModExpKAT[i].a, group.m_digitWidth, true);
        var a = group.createElementFromDigits(mathKATs.ModExpKAT[i].a);

        // c1 = a^-1 mod p
        // c2 = a^(p-2) mod p
        // c3 = a * c1 mod p
        group.inverse(a, c1);
        group.modexp(a, pm2, c2);
        group.multiply(a, c1, c3);

        cryptoMath.normalizeDigitArray(c1.m_digits);
        cryptoMath.normalizeDigitArray(c2.m_digits);
        cryptoMath.normalizeDigitArray(c3.m_digits);

        // Verify the results
        var pass = (c1.equals(c2)) &&
            (cryptoMath.compareDigits(c3.m_digits, one) == 0);

        ok(pass, "Multiplicative group inversion test. " +
            "c1=" + c1.toString() + "\n" +
            "c2=" + c2.toString() + "\n" +
            "c3=" + c3.toString()
            );
    }
});

test("IntegerGroup Add", function () {
    // 
    var numberOfTests = mathKATs.ModAddKAT.length;
    expect(numberOfTests);

    var cca = [];
    for (var i = 0; i < numberOfTests; ++i) {
        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(mathKATs.ModAddKAT[i].n));
        var a1 = group.createElementFromDigits(mathKATs.ModAddKAT[i].a1);
        var a2 = group.createElementFromDigits(mathKATs.ModAddKAT[i].a2);
        var s = group.createElementFromDigits(mathKATs.ModAddKAT[i].s);
        var ss = group.createElementFromInteger(0);

        // ss = a1 + a2 mod n
        group.add(a1, a2, ss);

        // Verify the results
        var pass = ss.equals(s);
        ok(pass, "IntegerGroup.add test. " +
            "s=" + s.toString() + "\n" +
            "ss=" + ss.toString()
            );
    }
});

test("IntegerGroup Subtract", function () {
    // 
    var numberOfTests = mathKATs.ModAddKAT.length;
    expect(numberOfTests);

    var aa2 = [];
    for (var i = 0; i < numberOfTests; ++i) {
        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(mathKATs.ModAddKAT[i].n));
        var a1 = group.createElementFromDigits(mathKATs.ModAddKAT[i].a1);
        var a2 = group.createElementFromDigits(mathKATs.ModAddKAT[i].a2);
        var s = group.createElementFromDigits(mathKATs.ModAddKAT[i].s);
        var aa2 = group.createElementFromInteger(0);

        // ss = a1 + a2 mod n
        group.subtract(s, a1, aa2);

        // Verify the results
        var pass = aa2.equals(a2);
        ok(pass, "IntegerGroup.subtract test. " +
            "a2=" + a2.toString() + "\n" +
            "aa2=" + aa2.toString()
            );
    }
});

test("IntegerGroup Multiply", function () {
    // ca = c1*c2 mod n
    var numberOfTests = mathKATs.ModExpKAT.length;
    expect(numberOfTests);

    var cca = [];
    for (var i = 0; i < numberOfTests; ++i) {
        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(mathKATs.ModExpKAT[i].n));
        var c1 = group.createElementFromDigits(mathKATs.ModExpKAT[i].c1);
        var c2 = group.createElementFromDigits(mathKATs.ModExpKAT[i].c2);
        var ca = group.createElementFromDigits(mathKATs.ModExpKAT[i].ca);
        var cca = group.createElementFromInteger(0);

        // cca = c1*c2 mod n
        group.multiply(c1, c2, cca);

        // Verify the results
        var pass = cca.equals(ca);
        ok(pass, "IntegerGroup.multiply test. " +
            "ca=" + ca.toString() + "\n" +
            "cca=" + cca.toString()
            );
    }
});

mathKATs.benchmarkShiftOrDivide = function (opType) {
    // select shift or division
    var loopCount = 10000;
    var ff = undefined;
    switch (opType) {
        case "rightshift":
            ff = function (number) { return number >> shift; };
            break;
        case "divide":
            ff = function (number) { return Math.floor(number / mathKATs.divTable[shift]); };
            break;
        case "leftshift":
            ff = function (number) { return number << shift; };
            break;
        case "multiply":
            ff = function (number) { return Math.floor(number * mathKATs.divTable[shift]); };
            break;
    }

    var number = 1234567890;
    for (i = 0; i < loopCount; ++i) {
        for (shift = 0; shift < 32; ++shift) {
            ff(number);
        }
    }
}

test("Benchmark: RightShift", function () {
    expect(1);
    var op = "rightshift";

    mathKATs.benchmarkShiftOrDivide(op);
    ok(true, "Benchmark: " + op);
});

test("Benchmark: Division", function () {
    expect(1);
    var op = "divide";

    mathKATs.benchmarkShiftOrDivide(op);
    ok(true, "Benchmark: " + op);
});

test("Benchmark: LeftShift", function () {
    expect(1);
    var op = "leftshift";

    mathKATs.benchmarkShiftOrDivide(op);
    ok(true, "Benchmark: " + op);
});

test("Benchmark: Multiply", function () {
    expect(1);
    var op = "multiply";

    mathKATs.benchmarkShiftOrDivide(op);
    ok(true, "Benchmark: " + op);
});
