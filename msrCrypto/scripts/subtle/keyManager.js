//*******************************************************************************
//
//    Copyright (c) 2018 Microsoft. All rights reserved.
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

// Storage for the keyData.
// Stored as {keyHandle: keyHandle, keyData: keyData} objects.
var keys = [];
keys.add = function (keyHandle, keyData) {
    keys.push({ keyHandle: keyHandle, keyData: keyData });
};
keys.remove = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            keys = keys.splice(i, 1);
            return;
        }
    }
};
keys.lookup = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            return keys[i].keyData;
        }
    }
    return null;
};