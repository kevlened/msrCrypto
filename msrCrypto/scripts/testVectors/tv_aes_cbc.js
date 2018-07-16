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

var testVectorsAESCBC = {
    "AES-CBC-128": [
    {
        key: "00000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        pt: "00000000000000000000000000000000",
        ct: "66E94BD4EF8A2C3B884CFA59CA342B2E9434DEC2D00FDAC765F00C0C11628CD1"
    }
    ],
    "AES-CBC-192": [
    {
        key: "000000000000000000000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        pt: "00000000000000000000000000000000",
        ct: "AAE06992ACBF52A3E8F4A96EC9300BD71045BE567103016AC50B21B86FC5457E"
    }
    ],
    "AES-CBC-256": [
    {
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "00000000000000000000000000000000",
        pt: "00000000000000000000000000000000",
        ct: "DC95C078A2408989AD48A21492842087F3C003DDC4A7B8A94BAEDFFC3D214C38"
    }
    ]
}