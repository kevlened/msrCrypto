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

/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.15.0.js" />

var rsaKey;

var privateKeyJson1024 =
    { 
        kty : "RSA", 
        ext : true, 
        n : "uA_jQfKOr8538LYmmOciUMqid7ixlCO9oIhdY9Gp5Vf4l2uMwL8NZLG90be7TTKuFAiY_0QfJVizd6N7QuvtvOoWCqaIM0hMUC_FSkSFXtLGtzY0FzNYUFQ3TUoubsk4cUF-07XQeV2KBYiNhhEkv_-u9MXSVTq1g8mqN46b73c", 
        e : "AQAB", 
        d : "Bo52U26O-584sYfjhxXQqJ0XPXmERdkiE5pX7UrWKPfBwK8Rk_oaQYh9UP-g-eaAwfDudkVYcK2gsvXNWbxquvz4uetnf9itE5UQ3fA4x_bg4qiI28ruhv0Na085A_3AHsVTrGmSvkPXBDal-2D8iw5EdeHmGjqx8CQluW_5d8k", 
        p : "xV0oJPFjzsQqJwp-j0l3-x_3zsmjT4nmeZHq_PbonrVm8GVdvg19I0bRp6f5lUWQ_PWKJK2PXzw-E8q3nxsuTw", 
        q : "7r8Jo-vg8jhz4G91j4q5-WNbn2UnNME1UYbp71AQeOf6wD7UFVpHObz5P1jMQRpXHKgu_XqDNOH10GzldVpKWQ", 
        dp : "UvB8D1JV5C1xnWh-mQ6B2kmr5P29oI5OCaa1fsrwJMoM0Vd31odqoCmBr5gafY13iaZSAGnjh10UpVKaacWNZw", 
        dq : "DahF_-eNba3HCy61FeoEq3yAkES0EnN-_lPua-8zkgcLNBYkAbixXF8wDuygepTsKMqCLaPlf4_xhOPF2Im6uQ", 
        qi : "qKuwiuJNnXia_PSamSJTojmOdwG1GYH_5qAhHIa1CjtMfXHLy7IzY1uErV6lJv-_qUSrYRMRtDSmY3sFQRir5g" 
    };

var publicKeyJson1024 =
    { 
        kty : "RSA", 
        ext : true, 
        n : "uA_jQfKOr8538LYmmOciUMqid7ixlCO9oIhdY9Gp5Vf4l2uMwL8NZLG90be7TTKuFAiY_0QfJVizd6N7QuvtvOoWCqaIM0hMUC_FSkSFXtLGtzY0FzNYUFQ3TUoubsk4cUF-07XQeV2KBYiNhhEkv_-u9MXSVTq1g8mqN46b73c", 
        e : "AQAB" 
    };

var privateKeyJson2048 =
    { 
        kty : "RSA",
        ext : true, 
        n : "uZQSanGzrG9aSPj3-yReDkFj4JDDPQJo5noV_HgntHhqyF6ZZPA3n4z4qmI39Hfjovv1EmWrS0aFofEBF-87EB0PF2Z445KMHFDQmv8kUe6wblf95EKQ0XI2OBadFaiIBIxgCmbG7o-pJQjY74U0KDMQEwe0DfMcfFZ_-y6vxEd-RNeff2Lm-sQlZ7E0HpBlwQGYHJZonv1mVuZuVlF1qDaam7V_8cF8MgrbqQP_xG4eM5odLNqAOTGNrtvo5XV-a5Qzd2gVqAc0VrayOUknjX_2OTndik5YWLspva6L-T07ysnMPqiqD0tTPcR_3hYHqNDKpWujbmtSevBOtLUgVw", 
        e : "AQAB", 
        d : "KZH2OBrlNRyyfEMtBXhli0rxjRXQbkOybOJvN2FQ_5ezz9OFB_vZceeZsk0THLOYbeODx823e8K934NFi-9-awMfZM4DCXND6Hnf6MB7idDue6FBUdbpaslrRNAn-viIE4DAaMQSDtFmgdHECo9rmg-qK6Efn7pUKLQVshYIsG4ytQ8Om6CJ8MVWR8hwL-65uSCSUElXDHaG-U8CkfivEIesVPfkQ65Cd16zPYlqIReRSaB_w2I7orf_1T5IY1aa0FuzBxEq1q8FPLQnZfIOCG_kMGhUnMJRx8NarQJUILbnKX7kNPMq-eiSvBuHBIFpsJ-VSDHpq9aPqQYskpsYCQ", 
        p : "_DYTq5Kr_c-abCL5yZ517mw_k3Hpruh3q9ibQVrjT10nuWlLwR8N_rv6uxs6t9qyfncXGPOjgMOvrSSWW49AzTLJ7DgCWtZvH1TKR4YilR3En2D9cww1f9iYCKBbyxvrT7X5mT9g2yGTxOoVObqq46GdaaNaWd8FuTpX-HEfjA8", 
        q : "vF2_J4nJHXFPxdJe_Om1xGJGp0eJVDfMY4YQBx2awW-sijjRUtqS8rH8ckPABvBEzYi95e1FoMwRVKo3XSlxPlBrJZHtsj3lVY83tDnO-Nv4rPCoX_nQFaVSVdmIVpiUF9yFrIjndtACppANAGcfhpZutrYjfru2NM6xOmkU_zk", 
        dp : "tT1K_1VkIP0ptCGiLH-hsZa6TQNj8Rv-u0_pqZpdlK-Vl0iSdpIRZYfCEujrViljcTu1LmoOib6VpK-RGPSllY-0yPoqvwovSm2M-r7qZQvCOuHg3-bbHycPgctyi09h1qMnXTfNK0tCvBOW8ygwG2oNC1em2sRIgaXqh48LI4M", 
        dq : "G_aKxxLUUVOd9Q8K3N7RBgtU08Zx45e49tlTDcteSvMKGSbgJD2gbPjxMgFOw3jtrdlr33M-z-UbeYcfWuwpDIghr90e_UPlBLOTIGUojZcSLpI3XLAYLO5y752weLKD4ZryGS_ltKSikBl4ZKPqcS9p1iPp1wmEvgglFTe-Tzk", 
        qi : "PZuSu0-5MEY0Zgry7_A9ZMN91tqSkcmEpfRVuKnilj8zNmOEAUyEq8lvMji5oFBxFKtx0pbqiK5tuxPecdwJ7Y8iYxu2Wb50IoORJggc4er6Q5NIA3_XKEn3x8GORqdibPuPHZXXjd4sG6dQIZJbWNEyzvzyRDfidrKZxS5yvIU" 
    };

var publicKeyJson2048 =
    { 
        kty : "RSA", 
        ext : true, 
        n : "uZQSanGzrG9aSPj3-yReDkFj4JDDPQJo5noV_HgntHhqyF6ZZPA3n4z4qmI39Hfjovv1EmWrS0aFofEBF-87EB0PF2Z445KMHFDQmv8kUe6wblf95EKQ0XI2OBadFaiIBIxgCmbG7o-pJQjY74U0KDMQEwe0DfMcfFZ_-y6vxEd-RNeff2Lm-sQlZ7E0HpBlwQGYHJZonv1mVuZuVlF1qDaam7V_8cF8MgrbqQP_xG4eM5odLNqAOTGNrtvo5XV-a5Qzd2gVqAc0VrayOUknjX_2OTndik5YWLspva6L-T07ysnMPqiqD0tTPcR_3hYHqNDKpWujbmtSevBOtLUgVw", 
        e : "AQAB" 
    };


function compareKeys(exportedKeyObject, expectedKeyObject) {



    for (var property in expectedKeyObject) {
        equal(exportedKeyObject[property], expectedKeyObject[property], "key." + property + " matches");
    }

}

function importRsaKey(keyJsonText, algorithm, callback, errorCallback) {

    var keyData = keyJsonText;

    subtle.importKey("jwk", keyData, algorithm, true, ["encrypt", "decrypt"]).then(
        function (e) {
            callback(e);
        },
        function (e) {
            errorCallback(e);
        }
    );
}

function importRsaKeyTest(jwkKeyObject, algorithmName, isPublic, isSync) {

    var rsaKey = null;

    var keyType = isPublic ? "public" : "private";
    var expectedKeyText = isPublic ? publicKeyJson2048 : privateKeyJson2048;
    var usage,
        hash = { name: "SHA-256" },
        algorithm = { name: algorithmName };


    subtle.forceSync = isSync;

    switch (algorithmName) {

        case ("rsaes-pkcs1-v1_5"):
            usage = ["encrypt", "decrypt"];
            break;

        case ("rsassa-pkcs1-v1_5"):
            usage = isPublic ? [] : ["sign"];
            algorithm.hash = hash;
            algorithm.publicExponent = shared.toSupportedArray([1, 0, 1]);
            break;

        case ("rsa-oaep"):
            usage = isPublic ? [] : ["decrypt"];
            algorithm.hash = hash;
            algorithm.publicExponent = shared.toSupportedArray([1, 0, 1]);;
            break;

        case ("rsa-pss"):
            usage = ["encrypt", "decrypt"];
            algorithm.hash = hash;
            algorithm.publicExponent = shared.toSupportedArray([1, 0, 1]);
            break;
    }


    subtle.importKey("jwk", jwkKeyObject, algorithm, true, usage)
        .then(

            function (importedKey) {
                rsaKey = importedKey;
                return subtle.exportKey("jwk", importedKey);
            },

            function (error) {
                return Promise.reject(error);
            }
        )
        .then(
            function (exportedKey) {
                start();
                equal(rsaKey.type, keyType, keyType + " key type");
                equal(rsaKey.algorithm.name.toUpperCase(), algorithmName.toUpperCase(), algorithmName + " algorithm name");
                compareKeys(exportedKey, expectedKeyText);
            },
            function (error) {
                start();
                ok(false, error);
                return;
            }
        )
    }

function rsaEncryptionComplete(context) {
    return function (e) {
        var encryptedBytes = shared.getArrayResult(e);
        rsaDecrypt(context.privateKey, context.algorithmName, encryptedBytes, context.sync, context.expectedResults);
    };
}

function rsaDecryptionComplete(expectedResults) {
    return function (e) {
        start();
        var decryptedBytes = shared.getArrayResult(e);
        var result = String.fromCharCode.apply(null, decryptedBytes);
        equal(result, expectedResults, result + " = " + expectedResults);
    };
}

function setAlgorithm(algorithmName, isPublic) {

    var usage,
        hash = { name: "SHA-256" },
        algorithm = { name: algorithmName };

    switch (algorithmName) {

        case ("rsaes-pkcs1-v1_5"):
            usage = ["encrypt", "decrypt"];
            break;

        case ("rsassa-pkcs1-v1_5"):
            usage = isPublic ? ["verify"] : ["sign"];
            algorithm.hash = hash;
            algorithm.publicExponent = shared.toSupportedArray([1, 0, 1]);
            break;

        case ("rsa-oaep"):
            usage = isPublic ? ["encrypt"] : ["decrypt"];
            algorithm.hash = hash;
            algorithm.publicExponent = shared.toSupportedArray([1, 0, 1]);
            break;

        case ("rsa-pss"):
            usage = isPublic ? ["verify"] : ["sign"];
            algorithm.hash = hash;
            algorithm.publicExponent = shared.toSupportedArray([1, 0, 1]);
            algorithm.saltLength = 32;
            break;
    }

    return {algorithm: algorithm, usage: usage};
}

function rsaEncrypt(publicKey, privateKey, algorithmName, dataBytes, sync) {

    var publicAlgorithm = setAlgorithm(algorithmName, true),
        privateAlgorithm = setAlgorithm(algorithmName, false),
        importedPublicKey,
        importedPrivateKey;

    subtle.forceSync = sync;

    subtle.importKey("jwk", publicKey, publicAlgorithm.algorithm, true, publicAlgorithm.usage)
        .then(
            function (result) {
                importedPublicKey = result;
                return subtle.importKey("jwk", privateKey, privateAlgorithm.algorithm, true, privateAlgorithm.usage);
            },
            function (failure) {
                return Promise.reject(failure);
            }
        )
        .then(
            function (result) {
                importedPrivateKey = result;
                return subtle.encrypt(publicAlgorithm.algorithm, importedPublicKey, dataBytes);
            },
            function (failure) {
                return Promise.reject(failure);
            }
        )
        .then(
            function (result) {
                return subtle.decrypt(privateAlgorithm.algorithm, importedPrivateKey, shared.toSupportedArray(result));
            },
            function (failure) {
                return Promise.reject(failure);
            }
        )
        .then(
            function (result) {
                start();
                var decryptedBytes = shared.getArrayResult(result).join();
                var expectedBytes = Array.apply(null, dataBytes).join();
                equal(decryptedBytes, expectedBytes, decryptedBytes + " = " + expectedBytes);
            },
            function (failure) {
                start();
                ok(false, failure);
                return;
            }
        );
}

function rsaDecrypt(privateKey, algorithmName, encryptedBytes, sync, expectedResults) {

    subtle.forceSync = sync;

    importRsaKey(privateKey, algorithmName, function (key) {

        var algObj = { name: algorithmName };

        if (algorithmName === "rsa-oaep") {
            algObj.hash = { name: 'sha-256' };
        }

        subtle.decrypt(algObj, key, shared.toSupportedArray(encryptedBytes)).then(
            rsaDecryptionComplete(expectedResults),
            shared.error
        );

    }, shared.error);
}

function rsaSignComplete(context) {
    return function (e) {
        var signature = shared.toSupportedArray(shared.getArrayResult(e));
        rsaVerify(context.publicKey,
                context.algorithmName,
                context.shaName,
                context.dataBytes,
                signature,
                context.sync,
                context.expectedResults);
    };
}

function rsaVerifyComplete(expectedResults) {
    return function (result) {
        start();
        equal(result, expectedResults, result + " = " + expectedResults);
    };
}


function rsaSign(publicKey, privateKey, algorithmName, shaName, dataBytes, expectedResult, sync) {

    var publicAlgorithm = setAlgorithm(algorithmName, true),
        privateAlgorithm = setAlgorithm(algorithmName, false),
        importedPublicKey,
        importedPrivateKey;

    subtle.forceSync = sync;

    subtle.importKey("jwk", publicKey, publicAlgorithm.algorithm, true, publicAlgorithm.usage)
        .then(
            function (result) {
                importedPublicKey = result;
                return subtle.importKey("jwk", privateKey, privateAlgorithm.algorithm, true, privateAlgorithm.usage);
            },
            function (failure) {
                return Promise.reject(failure);
            }
        )
        .then(
            function (result) {
                importedPrivateKey = result;
                return subtle.sign(privateAlgorithm.algorithm, importedPrivateKey, dataBytes);
            },
            function (failure) {
                return Promise.reject(failure);
            }
        )
        .then(
            function (result) {
                return subtle.verify(publicAlgorithm.algorithm, importedPublicKey, shared.toSupportedArray(result), dataBytes);
            },
            function (failure) {
                return Promise.reject(failure);
            }
        )
        .then(
            function (result) {
                start();
                ok(result, "verify");
            },
            function (failure) {
                start();
                ok(false, failure);
                return;
            }
        );
}


function rsaVerify(publicKey, algorithmName, shaName, dataBytes, signatureBytes, sync, expectedResults) {

    subtle.forceSync = sync;

    importRsaKey(publicKey, algorithmName, function (key) {

        var algObj = { name: algorithmName, hash: shaName };

        // If we expect to fail, we'll flip a random bit to force (hopefully) a failure.
        if (!expectedResults) {
            var randByte = Math.floor(Math.random() * dataBytes.length);
            dataBytes[randByte] = dataBytes[randByte] ^ 1;
        }

        subtle.verify(algObj, key, signatureBytes, dataBytes).then(
            rsaVerifyComplete(expectedResults),
            shared.error("verify error")
        );

    }, shared.error("import key error"));

}


module("RSA");

asyncTest("Public PKCSv15 KeyImport Sync", function () {

    expect(6);

    importRsaKeyTest(publicKeyJson2048, "rsaes-pkcs1-v1_5", true, true);

});

asyncTest("Public PKCSv15 KeyImport Async", function () {

    expect(6);

    importRsaKeyTest(publicKeyJson2048, "rsaes-pkcs1-v1_5", true, false);

});

asyncTest("Private PKCSv15 KeyImport Sync", function () {

    expect(12);

    importRsaKeyTest(privateKeyJson2048, "rsaes-pkcs1-v1_5", false, true);

});

asyncTest("Private PKCSv15 KeyImport Async", function () {

    expect(12);

    importRsaKeyTest(privateKeyJson2048, "rsaes-pkcs1-v1_5", false, false);

});

asyncTest("Public OAEP KeyImport Sync", function () {

    expect(6);

    importRsaKeyTest(publicKeyJson2048, "rsa-oaep", true, true);

});

asyncTest("Public OAEP KeyImport Async", function () {

    expect(6);

    importRsaKeyTest(publicKeyJson2048, "rsa-oaep", true, false);

});

asyncTest("Private OAEP KeyImport Sync", function () {

    expect(12);

    importRsaKeyTest(privateKeyJson2048, "rsa-oaep", false, true);

});

asyncTest("Private OAEP KeyImport Async", function () {

    expect(12);

    importRsaKeyTest(privateKeyJson2048, "rsa-oaep", false, false);

});

asyncTest("Public RSASSA-PKCS1-v1_5 KeyImport Sync", function () {

    expect(6);

    importRsaKeyTest(publicKeyJson2048, "rsassa-pkcs1-v1_5", true, true);

});

asyncTest("Public RSASSA-PKCS1-v1_5 KeyImport Async", function () {

    expect(6);

    importRsaKeyTest(publicKeyJson2048, "rsassa-pkcs1-v1_5", true, false);

});

asyncTest("Private RSASSA-PKCS1-v1_5 KeyImport Sync", function () {

    expect(12);

    importRsaKeyTest(privateKeyJson2048, "rsassa-pkcs1-v1_5", false, true);

});

asyncTest("Private RSASSA-PKCS1-v1_5 KeyImport Async", function () {

    expect(12);

    importRsaKeyTest(privateKeyJson2048, "rsassa-pkcs1-v1_5", false, false);

});

asyncTest("Encrypt/Decrypt PKCSv15 2048 Async", function () {

    rsaEncrypt(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsaes-pkcs1-v1_5",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false
    );

});

asyncTest("Encrypt/Decrypt PKCSv15 2048 Sync", function () {

    rsaEncrypt(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsaes-pkcs1-v1_5",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true
    );

});

asyncTest("Encrypt/Decrypt OAEP 2048 Async", function () {

    rsaEncrypt(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsa-oaep",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false
    );

});

asyncTest("Encrypt/Decrypt OAEP 2048 Sync", function () {

    rsaEncrypt(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsa-oaep",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true
    );

});

asyncTest("Encrypt/Decrypt PKCSv15 1024 Async", function () {

    rsaEncrypt(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsaes-pkcs1-v1_5",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false
    );

});

asyncTest("Encrypt/Decrypt PKCSv15 1024 Sync", function () {

    rsaEncrypt(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsaes-pkcs1-v1_5",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true
    );

});

asyncTest("Encrypt/Decrypt OAEP 1024 Async", function () {

    rsaEncrypt(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsa-oaep",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false
    );

});

asyncTest("Encrypt/Decrypt OAEP 1024 Sync", function () {

    rsaEncrypt(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsa-oaep",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true
    );

});


asyncTest("Sign/Verify PKCSv15 2048 Sha-256 Async", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsassa-pkcs1-v1_5",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PKCSv15 2048 Sha-384 Async", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsassa-pkcs1-v1_5",
        "sha-384",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PKCSv15 2048 Sha-512 Async", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsassa-pkcs1-v1_5",
        "sha-512",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PKCSv15 2048 Sha-256 Async (Fail)", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsassa-pkcs1-v1_5",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        false,
        false
    );

});

asyncTest("Sign/Verify PKCSv15 1024 Sha-256 Async", function () {

    rsaSign(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsassa-pkcs1-v1_5",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PKCSv15 1024 Sha-256 Async (Fail)", function () {

    rsaSign(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsassa-pkcs1-v1_5",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        false,
        false
    );

});


asyncTest("Sign/Verify PSS 2048 Sha-256 Async", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsa-pss",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PSS 2048 Sha-384 Async", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsa-pss",
        "sha-384",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PSS 2048 Sha-512 Async", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsa-pss",
        "sha-512",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PSS 2048 Sha-256 Async (Fail)", function () {

    rsaSign(
        publicKeyJson2048,
        privateKeyJson2048,
        "rsa-pss",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        false,
        false
    );

});

asyncTest("Sign/Verify PSS 1024 Sha-256 Async", function () {

    rsaSign(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsa-pss",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false,
        false
    );

});

asyncTest("Sign/Verify PSS 1024 Sha-256 Async (Fail)", function () {

    rsaSign(
        publicKeyJson1024,
        privateKeyJson1024,
        "rsa-pss",
        "sha-256",
        shared.textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        false,
        false
    );

});