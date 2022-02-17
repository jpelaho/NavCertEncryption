using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;

namespace NavX509Certificate
{
    public class Cert
    {

        public string EncrFolder { get; set; }

        public Cert()
        {
        }
        public string EncryptFile(string FileToEcrypt, string filePrefix, string rsaPublicKey)
        {
            try
            {
                // Get the certifcate to use to encrypt the key.
                X509Certificate2 cert = GetCertificateFromStore(rsaPublicKey);
                //X509Certificate2 cert = GetCertificateFromStore("CN=CERT_SIGN_TEST_CERT");
                if (cert == null)
                {
                    throw new Exception("Certificate '" + rsaPublicKey + "' not found.");
                }


                // Encrypt the file using the public key from the certificate.
                return EncryptFile(FileToEcrypt, filePrefix, (RSACryptoServiceProvider)cert.PublicKey.Key);
            }
            catch (DirectoryNotFoundException)
            {
                throw new Exception("Error: The directory specified could not be found.");
            }
            catch (IOException)
            {
                throw new Exception("Error: A file in the directory could not be accessed.");
            }
            catch (NullReferenceException)
            {
                throw new Exception("Certificate must be in trusted authorities store.");
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
            // Encrypt a file using a public key.
        private string EncryptFile(string inFile,string filePrefix, RSACryptoServiceProvider rsaPublicKey)
        {
            string outFile = "";
            using (AesManaged aesManaged = new AesManaged())
            {
                // Create instance of AesManaged for
                // symetric encryption of the data.
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;
                using (ICryptoTransform transform = aesManaged.CreateEncryptor())
                {
                    RSAPKCS1KeyExchangeFormatter keyFormatter = new RSAPKCS1KeyExchangeFormatter(rsaPublicKey);
                    byte[] keyEncrypted = keyFormatter.CreateKeyExchange(aesManaged.Key, aesManaged.GetType());

                    // Create byte arrays to contain
                    // the length values of the key and IV.
                    byte[] LenK = new byte[4];
                    byte[] LenIV = new byte[4];

                    int lKey = keyEncrypted.Length;
                    LenK = BitConverter.GetBytes(lKey);
                    int lIV = aesManaged.IV.Length;
                    LenIV = BitConverter.GetBytes(lIV);

                    // Write the following to the FileStream
                    // for the encrypted file (outFs):
                    // - length of the key
                    // - length of the IV
                    // - ecrypted key
                    // - the IV
                    // - the encrypted cipher content

                    int startFileName = inFile.LastIndexOf("\\") + 1;
                    // Change the file's extension to ".enc"
                    //outFile = EncrFolder + inFile.Substring(startFileName, inFile.LastIndexOf(".") - startFileName) + ".enc";

                    var navGeneratedFileName = inFile.Substring(startFileName, inFile.LastIndexOf(".") - startFileName);
                    outFile = EncrFolder +  filePrefix + "." + navGeneratedFileName;
                    Directory.CreateDirectory(EncrFolder);

                    using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                    {
                        outFs.Write(LenK, 0, 4);
                        outFs.Write(LenIV, 0, 4);
                        outFs.Write(keyEncrypted, 0, lKey);
                        outFs.Write(aesManaged.IV, 0, lIV);

                        // Now write the cipher text using
                        // a CryptoStream for encrypting.
                        using (CryptoStream outStreamEncrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                        {

                            // By encrypting a chunk at
                            // a time, you can save memory
                            // and accommodate large files.
                            int count = 0;
                            int offset = 0;

                            // blockSizeBytes can be any arbitrary size.
                            int blockSizeBytes = aesManaged.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];
                            int bytesRead = 0;

                            using (FileStream inFs = new FileStream(inFile, FileMode.Open))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    offset += count;
                                    outStreamEncrypted.Write(data, 0, count);
                                    bytesRead += blockSizeBytes;
                                }
                                while (count > 0);
                                inFs.Close();
                            }
                            outStreamEncrypted.FlushFinalBlock();
                            outStreamEncrypted.Close();
                        }
                        outFs.Close();
                    }
                }
            }
            return outFile;
        }

        private X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            //X509Store store = new X509Store(StoreLocation.CurrentUser);
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                //X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = certCollection.Find(X509FindType.FindByIssuerName, certName, true);
                if (signingCert.Count == 0)
                    return null;
                // Return the first certificate in the collection, has the right name and is current.
                return signingCert[0];
            }
            finally
            {
                store.Close();
            }

        }

        public static void EncryptPgpFile(string inputFile, string outputFile, string publicKeyFile, bool armor, bool withIntegrityCheck)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyFile))
            {
                PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

                using (MemoryStream outputBytes = new MemoryStream())
                {
                    PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                    PgpUtilities.WriteFileToLiteralData(dataCompressor.Open(outputBytes), PgpLiteralData.Binary, new FileInfo(inputFile));

                    dataCompressor.Close();
                    PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                    dataGenerator.AddMethod(pubKey);
                    byte[] dataBytes = outputBytes.ToArray();

                    using (Stream outputStream = File.Create(outputFile))
                    {
                        if (armor)
                        {
                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                            {
                                using (Stream outputStream1 = dataGenerator.Open(armoredStream, dataBytes.Length))
                                {
                                    outputStream.Write(dataBytes, 0, dataBytes.Length);
                                }
                            }
                        }
                        else
                        {
                            using (Stream outputStream1 = dataGenerator.Open(outputStream, dataBytes.Length))
                            {
                                outputStream.Write(dataBytes, 0, dataBytes.Length);
                            }
                        }
                    }
                }
            }
        }

        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                        return key;
                }
            }
            throw new ArgumentException("Can't find encryption key in key ring.");
        }
    }


}
