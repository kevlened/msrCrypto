using Microsoft.Camelot.Math;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Web.Script.Services;
using System.Web.Services;
using camelot = Microsoft.Camelot.Cryptography;

namespace msrCrypto
{

    public static class Base64Url
    {
        public static string to(byte[] bytes)
        {
            string result = Convert.ToBase64String(bytes);
            result = result.Replace('+', '-');
            result = result.Replace('/', '_');
            return result.Replace("=", "");
        }

        public static byte[] from(string base64UrlString)
        {
            base64UrlString = base64UrlString.Replace('-', '+');
            base64UrlString = base64UrlString.Replace('_', '/');

            while ((base64UrlString.Length % 4) > 0)
            {
                base64UrlString += "=";
            }

            byte[] result = Convert.FromBase64String(base64UrlString);

            //Array.Resize<byte>(ref result, 32);

            return result;
        }
    }

    /// <summary>
    /// Summary description for DotNetWebService
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [ToolboxItem(false)]
    [ScriptService]
    public class DotNetWebService : WebService
    {
        private static JavaScriptSerializer serializer = new JavaScriptSerializer();

        private static ASCIIEncoding ByteConverter = new ASCIIEncoding();

        private static RandomNumberGenerator rng = new RandomNumberGenerator();

        [WebMethod]
        public byte[] getRandomBytes(int numberOfBytes)
        {
            RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();

            byte[] bytes = new byte[numberOfBytes];

            random.GetBytes(bytes);

            return bytes; // Convert.ToBase64String(bytes);
        }

        [WebMethod]
        public jwkKeyPair getRsaKeyPair(int keySize)
        {
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(keySize);
            RSAParameters rsaParams = rsaCsp.ExportParameters(true);

            jwkKeyPair keyPair = new jwkKeyPair(rsaParams);

            return keyPair;
        }

        [WebMethod]
        public jwkKeyPair getEcKeyPair(string curveName)
        {
            EllipticCurveFp e = selectCamelotCurve(curveName);

            camelot.ECKeyPair ecKeyPair = new camelot.ECKeyPair(e, rng);

            jwkKeyPair keyPair = new jwkKeyPair(ecKeyPair, curveName);

            return keyPair;
        }

        [WebMethod]
        public Object decrypt(jwkPrivateKey privateKey, byte[] cipherBytes, string hashAlgorithm)
        {
            rsaPrivateKey rsaKey = new rsaPrivateKey(privateKey);
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
            RSAParameters rsaParams = rsaKey.toRSAParameters();
            rsaCsp.ImportParameters(rsaParams);

            byte[] decryptedBytes;

            try
            {
                if (hashAlgorithm == null)
                {
                    decryptedBytes = rsaCsp.Decrypt(cipherBytes, false);
                }
                else
                {
                    decryptedBytes = decryptCamelotOAEP(rsaParams, hashAlgorithm, cipherBytes);
                }
            }
            catch (Exception ex)
            {
                return new Error(ex);
            }

            return decryptedBytes;
        }

        [WebMethod]
        public Object encrypt(jwkPublicKey publicKey, byte[] plainBytes, string hashAlgorithm)
        {
            rsaPublicKey rsaKey = new rsaPublicKey(publicKey);
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
            RSAParameters rsaParams = rsaKey.toRSAParameters();
            rsaCsp.ImportParameters(rsaParams);

            byte[] encryptedBytes;

            try
            {
                if (hashAlgorithm == null)
                {
                    encryptedBytes = rsaCsp.Encrypt(plainBytes, false);
                }
                else
                {
                    rsaParams = rsaCsp.ExportParameters(false);
                    encryptedBytes = encryptCamelotOAEP(rsaParams, hashAlgorithm, plainBytes);
                }
            }
            catch (Exception ex)
            {
                return new Error(ex);
            }

            return encryptedBytes;

        }

        [WebMethod]
        public Object sign(string mode, jwkPrivateKey privateKey, byte[] plainBytes, string hashAlgorithm, string curveName)
        {
            byte[] signature;

            if (mode == "ecdsa")
            {
                EllipticCurveFp curve = selectCamelotCurve(curveName);

                ecPrivateKey ecPrivateKey = new ecPrivateKey(privateKey);

                camelot.ECKeyPair ecKeyPairPrivate = new camelot.ECKeyPair(curve, ecPrivateKey.D, null);

                camelot.HashAlgorithm h = selectCamelotHashAlgorithm(hashAlgorithm);

                byte[] digest = h.ComputeHash(plainBytes);

                signature = signCamelotEcdsa(ecKeyPairPrivate, digest);

            }
            else
            {
                rsaPrivateKey rsaKey = new rsaPrivateKey(privateKey);
                RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
                RSAParameters rsaParams = rsaKey.toRSAParameters();
                rsaCsp.ImportParameters(rsaParams);

                if (mode == "rsa-pss")
                {
                    signature = signCamelotPSS(rsaParams, hashAlgorithm, plainBytes);
                }
                else if (mode == "rsassa-pkcs1-v1_5")
                {
                    signature = rsaCsp.SignData(plainBytes, selectCSPHashAlgorithm(hashAlgorithm));
                }
                else
                {
                    throw new InvalidOperationException("Unsupported mode");
                }
            }

            return signature;

        }

        [WebMethod]
        public Object verify(String mode, jwkPublicKey publicKey, byte[] plainBytes, string hashAlgorithm, string curveName, byte[] signatureBytes)
        {
            bool verified = false;

            if (mode == "ecdsa")
            {
                EllipticCurveFp curve = selectCamelotCurve(curveName);

                ecPublicKey ecPublicKey = new ecPublicKey(publicKey);

                EllipticCurvePointFp point =
                    new EllipticCurvePointFp(curve, false, ecPublicKey.X, ecPublicKey.Y);

                camelot.ECKeyPair ecKeyPair =
                    new camelot.ECKeyPair(curve, SEC1EncodingFp.EncodePoint(point));

                camelot.HashAlgorithm h = selectCamelotHashAlgorithm(hashAlgorithm);

                byte[] digest = h.ComputeHash(plainBytes);

                verified = verifyCamelotEcdsa(ecKeyPair, digest, signatureBytes);
            }
            else
            {
                rsaPublicKey rsaKey = new rsaPublicKey(publicKey);
                RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
                RSAParameters rsaParams = rsaKey.toRSAParameters();
                rsaCsp.ImportParameters(rsaParams);

                if (mode == "rsa-pss")
                {
                    verified = verifyCamelotPSS(rsaParams, hashAlgorithm, plainBytes, signatureBytes);
                }
                else if (mode == "rsassa-pkcs1-v1_5")
                {
                    verified = rsaCsp.VerifyData(plainBytes, selectCSPHashAlgorithm(hashAlgorithm), signatureBytes);
                }
                else
                {
                    throw new InvalidOperationException("Unsupported mode");
                }
            }

            return verified;
        }

        [WebMethod]
        public Object deriveBits(jwkPublicKey publicKey, string hashAlgorithmName)
        {
            CngAlgorithm alg = selectCngCurve(publicKey.crv);

            // Generate a new key pair
            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.ExportPolicy = CngExportPolicies.AllowExport;
            keyCreationParameters.KeyUsage = CngKeyUsages.KeyAgreement;
            CngKey serverKeyPair = CngKey.Create(alg, null, keyCreationParameters);

            CngKey clientPubicKey = publicKey.toPublicCngKey();

            ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng(serverKeyPair);
            ecdh.HashAlgorithm = selectCngHashAlgorithm(hashAlgorithmName);

            byte[] keyMaterial = ecdh.DeriveKeyMaterial(clientPubicKey);

            return new object[] { new jwkPublicKey(serverKeyPair), keyMaterial };
        }

        private byte[] decryptCamelotOAEP(RSAParameters rsaParams, string hashAlgorithm, byte[] cipherBytes)
        {
            try
            {
                camelot.RSAManaged myRsaCsp =
                    new camelot.RSAManaged(rsaParams.D, null, rsaParams.Modulus);

                camelot.HashAlgorithm hashAlg = selectCamelotHashAlgorithm(hashAlgorithm);

                // Decrypt using Camelot OAEP + SHA2
                camelot.RSAOAEPKeyExchangeDeformatter netOaepDeformatter1 =
                    new camelot.RSAOAEPKeyExchangeDeformatter(myRsaCsp, hashAlg);

                byte[] decryptedActual =
                    netOaepDeformatter1.DecryptKeyExchange(cipherBytes);

                return decryptedActual;
            }
            catch (Exception ex)
            {
                return ByteConverter.GetBytes(ex.Message);
            }
        }

        private byte[] encryptCamelotOAEP(RSAParameters rsaParams, string hashAlgorithm, byte[] plainBytes)
        {
            try
            {
                camelot.RSAManaged myRsaCsp =
                    new camelot.RSAManaged(null, rsaParams.Exponent, rsaParams.Modulus);

                camelot.HashAlgorithm hashAlg = selectCamelotHashAlgorithm(hashAlgorithm);

                // Decrypt using Camelot OAEP + SHA2
                camelot.RSAOAEPKeyExchangeFormatter netOaepFormatter =
                    new camelot.RSAOAEPKeyExchangeFormatter(myRsaCsp, hashAlg, rng);

                byte[] cipherBytes =
                    netOaepFormatter.CreateKeyExchange(plainBytes);

                return cipherBytes;
            }
            catch (Exception ex)
            {
                return ByteConverter.GetBytes(ex.Message);
            }
        }

        private byte[] signCamelotPSS(RSAParameters rsaParams, string hashAlgorithm, byte[] plainBytes)
        {

            try
            {
                camelot.RSAManaged myRsaCsp =
                    new camelot.RSAManaged(rsaParams.D, null, rsaParams.Modulus);

                camelot.HashAlgorithm hashAlg = selectCamelotHashAlgorithm(hashAlgorithm);

                // Decrypt using Camelot OAEP + SHA2
                camelot.RSAPSSSignatureFormatter netPssFormatter =
                    new camelot.RSAPSSSignatureFormatter(myRsaCsp, hashAlg, rng);

                byte[] signatureBytes =
                    netPssFormatter.CreateSignature(plainBytes);

                return signatureBytes;
            }
            catch (Exception ex)
            {
                return ByteConverter.GetBytes(ex.Message);
            }

        }

        private Boolean verifyCamelotEcdsa(camelot.ECKeyPair keyPair, byte[] digest, byte[] signature)
        {
            try
            {
                bool verified = camelot.ECDSA.ECDSAVerify(keyPair, digest, signature);

                return verified;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private byte[] signCamelotEcdsa(camelot.ECKeyPair keyPair, byte[] plain)
        {
            try
            {
                byte[] signature = camelot.ECDSA.ECDSASign(keyPair, plain, rng);

                return signature;
            }
            catch (Exception ex)
            {
                return ByteConverter.GetBytes(ex.Message);
            }
        }

        private Boolean verifyCamelotPSS(RSAParameters rsaParams, string hashAlgorithm, byte[] plainBytes, byte[] signatureBytes)
        {

            try
            {
                camelot.RSAManaged myRsaCsp =
                    new camelot.RSAManaged(null, rsaParams.Exponent, rsaParams.Modulus);

                camelot.HashAlgorithm hashAlg = selectCamelotHashAlgorithm(hashAlgorithm);

                // Decrypt using Camelot OAEP + SHA2
                camelot.RSAPSSSignatureDeformatter netPssDeformatter =
                    new camelot.RSAPSSSignatureDeformatter(myRsaCsp, hashAlg);

                Boolean verified =
                    netPssDeformatter.VerifySignature(plainBytes, signatureBytes);

                return verified;
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        private System.Security.Cryptography.HashAlgorithm selectCSPHashAlgorithm(string hashAlgorithmName)
        {

            switch (hashAlgorithmName.ToLower())
            {
                case "sha-1":
                    return new SHA1CryptoServiceProvider();

                case "sha-256":
                    return new SHA256CryptoServiceProvider();

                case "sha-384":
                    return new SHA384CryptoServiceProvider();

                case "sha-512":
                    return new SHA512CryptoServiceProvider();

                default:
                    throw new InvalidOperationException("Unsupported hash algoritmn");
            }

        }

        private camelot.HashAlgorithm selectCamelotHashAlgorithm(string algorithmName)
        {
            // Encrypt using Camelot OAEP + SHA256
            switch (algorithmName)
            {
                case "sha-1":
                    return new camelot.SHA1Managed();

                case "sha-256":
                    return new camelot.SHA256Managed();

                case "sha-384":
                    return new camelot.SHA384Managed();

                case "sha-512":
                    return new camelot.SHA512Managed();

                default:
                    throw new Exception("Unsupported hash algroithm.");
            }
        }

        private CngAlgorithm selectCngHashAlgorithm(string algorithmName)
        {
            // Encrypt using Camelot OAEP + SHA256
            switch (algorithmName)
            {
                case "sha-1":
                    return CngAlgorithm.Sha1;

                case "sha-256":
                    return CngAlgorithm.Sha256;

                case "sha-384":
                    return CngAlgorithm.Sha384;

                case "sha-512":
                    return CngAlgorithm.Sha512;

                default:
                    throw new Exception("Unsupported hash algroithm.");
            }
        }

        private EllipticCurveFp selectCamelotCurve(string curveName)
        {
            // Encrypt using Camelot OAEP + SHA256
            switch (curveName.ToLower())
            {
                case "p-256":
                    return EllipticCurveFp.CreateP256();

                case "p-384":
                    return EllipticCurveFp.CreateP384();

                default:
                    throw new InvalidOperationException("Unsupported curve");
            }
        }

        private CngAlgorithm selectCngCurve(string curveName)
        {
            // Encrypt using Camelot OAEP + SHA256
            switch (curveName.ToLower())
            {
                case "p-256":
                    return CngAlgorithm.ECDiffieHellmanP256;

                case "p-384":
                    return CngAlgorithm.ECDiffieHellmanP384;

                default:
                    throw new InvalidOperationException("Unsupported curve");
            }
        }

        private RSACryptoServiceProvider importKey(string encodedKey)
        {
            byte[] keyBytes = Convert.FromBase64String(encodedKey);

            string keyJson = ByteConverter.GetString(keyBytes);

            jwkPrivateKey key = serializer.Deserialize<jwkPrivateKey>(keyJson);

            Object rsaKey;
            RSAParameters rsaParams;

            if (key.d != null)
            {
                rsaKey = new rsaPrivateKey(key);
                rsaParams = (rsaKey as rsaPrivateKey).toRSAParameters();
            }
            else
            {
                rsaKey = new rsaPublicKey(key);
                rsaParams = (rsaKey as rsaPublicKey).toRSAParameters();
            }

            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
            rsaCsp.ImportParameters(rsaParams);

            return rsaCsp;
        }

        public class Error
        {

            public string error;
            public string stackTrace;

            public Error()
            {
            }

            public Error(Exception ex)
            {
                this.error = ex.Message;
                this.stackTrace = ex.StackTrace;
            }
        }

        public class RandomNumberGenerator : Microsoft.Camelot.Math.IRandom
        {
            private RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

            /// <summary>
            /// Fills the elements of the given array with random bits.
            /// </summary>
            /// <param name="buffer">An array of bytes to contain random numbers.</param>
            public void NextBytes(byte[] buffer)
            {
                rng.GetBytes(buffer);
            }

            /// <summary>
            /// Returns a non-negative random number less than the specified value.
            /// </summary>
            /// <param name="maxValue">The exclusive upper bound of the 
            /// random number to be generated. maxValue must be greater than
            /// or equal to zero.</param>
            /// <returns>A 32-bit signed integer greater than or equal to zero, and 
            /// less than maxValue; that is, the range of return values ordinarily 
            /// includes zero but not maxValue. However, if maxValue equals zero, 
            /// maxValue is returned.</returns>
            public int Next(int maxValue)
            {
                if (maxValue < 0)
                {
                    throw new ArgumentException("maxValue must be greater than or equal to zero.");
                }

                if (maxValue == 0) return 0;

                // Construct bit mask 
                int maxValueShifted = maxValue;
                int shift = 1;
                while ((maxValueShifted & 0x40000000) == 0x00000000)
                {
                    maxValueShifted = maxValueShifted << 1;
                    shift++;
                }

                uint maskValue = 0xFFFFFFFF << shift;
                maskValue = maskValue >> shift;

                byte[] mask = BitConverter.GetBytes(maskValue);

                // Get random number, mask, compare, until in range
                byte[] valueBytes = new byte[sizeof(int)];
                int randomNum = 0;
                do
                {
                    rng.GetBytes(valueBytes);
                    for (int i = 0; i < sizeof(int); i++)
                    {
                        valueBytes[i] = (byte)(valueBytes[i] & mask[i]);
                    }

                    randomNum = BitConverter.ToInt32(valueBytes, 0);
                } while (randomNum >= maxValue);

                // Ensure we are good to go
                Debug.Assert(randomNum >= 0);
                Debug.Assert(randomNum < maxValue);

                return randomNum;
            }
        }

    }


}
