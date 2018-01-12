using Microsoft.Camelot.Math;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Script.Serialization;
using camelot = Microsoft.Camelot.Cryptography;

namespace msrCrypto
{
    public class rsaPrivateKey
    {
        public byte[] Modulus, Exponent, D, P, Q, DP, DQ, InverseQ;

        public rsaPrivateKey()
        {
        }

        public rsaPrivateKey(jwkPrivateKey jwkFormatKey)
        {
            this.Modulus = Base64Url.from(jwkFormatKey.n);
            this.Exponent = Base64Url.from(jwkFormatKey.e);
            this.D = Base64Url.from(jwkFormatKey.d);
            this.P = Base64Url.from(jwkFormatKey.p);
            this.Q = Base64Url.from(jwkFormatKey.q);
            this.DP = Base64Url.from(jwkFormatKey.dp);
            this.DQ = Base64Url.from(jwkFormatKey.dq);
            this.InverseQ = Base64Url.from(jwkFormatKey.qi);
        }

        public RSAParameters toRSAParameters()
        {
            RSAParameters rsap = new RSAParameters();
            rsap.D = this.D;
            rsap.DP = this.DP;
            rsap.DQ = this.DQ;
            rsap.Modulus = this.Modulus;
            rsap.Exponent = this.Exponent;
            rsap.InverseQ = this.InverseQ;
            rsap.P = this.P;
            rsap.Q = this.Q;
            return rsap;
        }
    }

    public class rsaPublicKey
    {
        public byte[] Modulus, Exponent;

        public rsaPublicKey()
        {
        }

        public rsaPublicKey(jwkPublicKey jwkFormatKey)
        {
            this.Modulus = Base64Url.from(jwkFormatKey.n);
            this.Exponent = Base64Url.from(jwkFormatKey.e);
        }

        public RSAParameters toRSAParameters()
        {
            RSAParameters rsap = new RSAParameters();
            rsap.Modulus = this.Modulus;
            rsap.Exponent = this.Exponent;
            return rsap;
        }
    }

    public class ecPrivateKey
    {
        public byte[] D;

        public ecPrivateKey()
        {
        }

        public ecPrivateKey(jwkPrivateKey jwkFormatKey)
        {
            this.D = Base64Url.from(jwkFormatKey.d);
        }

    }

    public class ecPublicKey
    {
        public byte[] X, Y;

        public ecPublicKey()
        {
        }

        public ecPublicKey(jwkPublicKey jwkFormatKey)
        {
            this.X = Base64Url.from(jwkFormatKey.x);
            this.Y = Base64Url.from(jwkFormatKey.y);
        }

    }

    public class jwkPublicKey
    {
        public string kty;
        public string crv;
        public bool extractable;
        public string n, e, x, y;
        public jwkPublicKey()
        {
        }
        public jwkPublicKey(RSAParameters rsaKey)
        {
            this.kty = "RSA";
            this.extractable = true;
            this.n = Base64Url.to(rsaKey.Modulus);
            this.e = Base64Url.to(rsaKey.Exponent);
        }
        public jwkPublicKey(camelot.ECKeyPair ecKeyPair, string curveName)
        {
            EllipticCurvePointFp point =
                SEC1EncodingFp.DecodePoint(ecKeyPair.ExportPublicKey(), ecKeyPair.Curve);

            this.crv = curveName;
            this.kty = "EC";
            this.extractable = true;

            byte[] xBytes = point.X.ToByteArrayUnsigned();
            Array.Reverse(xBytes);

            byte[] yBytes = point.Y.ToByteArrayUnsigned();
            Array.Reverse(yBytes);

            this.x = Base64Url.to(xBytes);
            this.y = Base64Url.to(yBytes);
        }

        public jwkPublicKey(CngKey cngKey)
        {
            switch (cngKey.Algorithm.Algorithm)
            {
                case "ECDH_P256":
                    this.crv = "P-256";
                    break;

                case "ECDH_P384":
                    this.crv = "P-384";
                    break;

                default:
                    throw new InvalidOperationException("Unsupported curve");
            }

            this.kty = "EC";
            this.extractable = true;

            byte[] keyBlob = cngKey.Export(CngKeyBlobFormat.EccPublicBlob);

            // bytes 0-3 curve type; byte 4-7 key length; x bytes; y bytes
            var keyLen = keyBlob[4];

            byte[] xbytes = new byte[keyLen];
            byte[] ybytes = new byte[keyLen];

            Array.Copy(keyBlob, 8, xbytes, 0, keyLen);
            Array.Copy(keyBlob, 8 + xbytes.Length, ybytes, 0, keyLen);

            this.x = Base64Url.to(xbytes);
            this.y = Base64Url.to(ybytes);
        }

        public CngKey toPublicCngKey()
        {
            // BCRYPT_ECDH_PRIVATE_P256_MAGIC  0x324B4345 
            // BCRYPT_ECDH_PRIVATE_P384_MAGIC  0x344B4345 

            byte[] magic, keyLen;

            if (crv.ToLower() == "p-256")
            {
                // BCRYPT_ECDH_PUBLIC_P256_MAGIC   0x314B4345
                magic = new byte[] { 0x45, 0x43, 0x4B, 0x31 };
                keyLen = new byte[] { 32, 0, 0, 0 };
            }
            else if (crv.ToLower() == "p-384")
            {
                // BCRYPT_ECDH_PUBLIC_P384_MAGIC   0x334B4345
                magic = new byte[] { 0x45, 0x43, 0x4B, 0x33 };
                keyLen = new byte[] { 48, 0, 0, 0 };
            }
            else
            {
                throw new InvalidOperationException("Unsupported curve");
            }

            byte[] xbytes = Base64Url.from(this.x);
            byte[] ybytes = Base64Url.from(this.y);

            byte[] blob = new byte[xbytes.Length + ybytes.Length + magic.Length + 4];

            magic.CopyTo(blob, 0);
            keyLen.CopyTo(blob, 4);
            xbytes.CopyTo(blob, 8);
            ybytes.CopyTo(blob, xbytes.Length + 8);

            CngKey cngKey = CngKey.Import(blob, CngKeyBlobFormat.EccPublicBlob);

            return cngKey;
        }

    }

    public class jwkPrivateKey : jwkPublicKey
    {
        public string d, p, q, dp, dq, qi;
        public jwkPrivateKey()
        {
        }
        public jwkPrivateKey(RSAParameters rsaKey)
            : base(rsaKey)
        {
            this.d = Base64Url.to(rsaKey.D);
            this.p = Base64Url.to(rsaKey.P);
            this.q = Base64Url.to(rsaKey.Q);
            this.dp = Base64Url.to(rsaKey.DP);
            this.dq = Base64Url.to(rsaKey.DQ);
            this.qi = Base64Url.to(rsaKey.InverseQ);
        }
        public jwkPrivateKey(camelot.ECKeyPair ecKeyPair, string curveName)
            : base(ecKeyPair, curveName)
        {
            this.d = Base64Url.to(ecKeyPair.ExportPrivateKey());
        }
    }

    public class jwkKeyPair
    {
        public string publicKey;
        public string privateKey;

        private static JavaScriptSerializer serializer = new JavaScriptSerializer(/*ctr*/);

        public jwkKeyPair()
        { }

        public jwkKeyPair(RSAParameters rsaParams)
        {
            this.publicKey = serializer.Serialize(new jwkPublicKey(rsaParams));
            this.privateKey = serializer.Serialize(new jwkPrivateKey(rsaParams));
        }

        public jwkKeyPair(camelot.ECKeyPair ecKeyPair, string curveName)
        {
            this.publicKey = serializer.Serialize(new jwkPublicKey(ecKeyPair, curveName));
            this.privateKey = serializer.Serialize(new jwkPrivateKey(ecKeyPair, curveName));
        }

        public string serialize()
        {
            string serializedKeyPair = serializer.Serialize(this);
            return serializedKeyPair;
        }
    }

}