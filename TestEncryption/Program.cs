using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Text;
using NavX509Certificate;
using NavX509Cert;
using GpgApi;
using System.Threading;
using System.Collections.Generic;

// To run this sample use the Certificate Creation Tool (Makecert.exe) to generate a test X.509 certificate and 
// place it in the local user store. 
// To generate an exchange key and make the key exportable run the following command from a Visual Studio command prompt: 

//makecert -r -pe -n "CN=CERT_SIGN_TEST_CERT" -b 01/01/2010 -e 01/01/2012 -sky exchange -ss my
namespace X509CertEncrypt
{
    class Program
    {

        // Path variables for source, encryption, and
        // decryption folders. Must end with a backslash.
        private static string encrFolder = @"C:\OBJ\Encrypt\";
        private static string decrFolder = @"C:\OBJ\Decrypt\";
        private static string originalFile = "TestData.txt";
        private static string encryptedFile = "TestData.enc";

        private static string publicKeyPathFileName = "socgen.encryption.prod.txt";

        static void Main(string[] args)
        {
            var code = new Pgp();

            // Create an input file with test data.
            StreamWriter sw = File.CreateText(originalFile);
            sw.WriteLine("Test data to be encrypted");
            sw.Close();

            #region comment
            //// Get the certifcate to use to encrypt the key.
            //string certName = "CERT_SIGN_TEST_CERT";
            //X509Certificate2 cert = GetCertificateFromStoreLocal(certName);
            //if (cert == null)
            //{
            //    cert = GetCertificateFromStore(certName);
            //}
            //if (cert == null)
            //{
            //    Console.WriteLine("Certificatge 'CN=CERT_SIGN_TEST_CERT' not found.");
            //    Console.ReadLine();
            //}


            //// Encrypt the file using the public key from the certificate.
            //EncryptFile(originalFile, (RSACryptoServiceProvider)cert.PublicKey.Key);

            ////NavX509Certificate.Cert cert1 = new NavX509Certificate.Cert();
            ////cert1.EncrFolder = encrFolder;
            ////var outputFile=cert1.EncryptFile(@"C:\OBJ\Decrypt\" + originalFile, "pain.001.001.03.mctJP", "AfricasecurityCA") ;

            ////encryptedFile = encrFolder + outputFile;
            ////File.Create(encryptedFile);

            //// Decrypt the file using the private key from the certificate.
            //DecryptFile(encryptedFile, (RSACryptoServiceProvider)cert.PrivateKey); 
            #endregion

            var inputFile = decrFolder + originalFile;
            var outputFile = encrFolder + encryptedFile;
            var publicKeyPath = encrFolder + publicKeyPathFileName;
            //Cert.EncryptPgpFile(inputFile, outputFile, publicKeyPath, true, true);

            //Pgp.EncryptFile(inputFile, outputFile, publicKeyPath, true, true);
            //GpgApi.GpgEncrypt encr =new  GpgApi.GpgEncrypt()
            GpgInterface.ExePath = @"C:\Program Files (x86)\GnuPG\bin\gpg.exe";
            GpgInterface.SynchronizationContext = SynchronizationContext.Current;

            //GpgImportKey.ExePath = @"C:\Program Files (x86)\GnuPG\bin\gpg.exe";
            //GpgImportKey.SynchronizationContext = SynchronizationContext.Current;
            //GpgImportKey.GetSecureStringFromString()

            GpgListPublicKeys publicKeys = new GpgListPublicKeys();
            publicKeys.Execute();
            
            var recipients = new List<KeyId>();
            var gotTheKey = false;
            var email = "Cmi.Gestre@socgen.com";
            publicKeys.Execute();
            foreach (var key in publicKeys.Keys)
            {
                foreach (KeyUserInfo t in key.UserInfos)
                {
                    if (t.Email == email)
                    {
                        recipients.Add(key.Id);
                        gotTheKey = true;
                    }
                }
            }
            if (!gotTheKey)
            {
                throw new Exception(string.Format("pgp key with email address was not found",email));
            }
            //foreach (Key key in publicKeys.Keys)
            //{
            //    Console.WriteLine(key.Id);
            //    Console.WriteLine(key.UserInfos[0].Email);
            //}

            var encrypt = new GpgEncrypt(inputFile, outputFile, false, false, null, recipients, CipherAlgorithm.None);
            var encResult = encrypt.Execute();

            //GpgInterface.SynchronizationContext=new System.Threading.SynchronizationContext()

            //Display the original data and the decrypted data.
            Console.WriteLine("Original:   {0}", File.ReadAllText(originalFile));
            Console.WriteLine("Round Trip: {0}", File.ReadAllText(decrFolder + originalFile));
            Console.WriteLine("Press the Enter key to exit.");
            Console.ReadLine();
        }
        private static X509Certificate2 GetCertificateFromStore(string certName)
        {

            // Get the certificate store for the current user.
            //X509Store store = new X509Store(StoreLocation.CurrentUser);
            X509Store store = new X509Store(StoreName.Root,StoreLocation.LocalMachine);
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
        private static X509Certificate2 GetCertificateFromStoreLocal(string certName)
        {

            // Get the certificate store for the current user.
            X509Store store = new X509Store(StoreLocation.CurrentUser);
            //X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadOnly);

                // Place all certificates in an X509Certificate2Collection object.
                X509Certificate2Collection certCollection = store.Certificates;
                // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
                // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
                //X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = certCollection.Find(X509FindType.FindByIssuerName, certName, false);
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

        // Encrypt a file using a public key.
        private static void EncryptFile(string inFile, RSACryptoServiceProvider rsaPublicKey)
        {
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
                    string outFile = encrFolder + inFile.Substring(startFileName, inFile.LastIndexOf(".") - startFileName) + ".enc";
                    
                    
                    
                    
                    Directory.CreateDirectory(encrFolder);

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
        }


        // Decrypt a file using a private key.
        private static void DecryptFile(string inFile, RSACryptoServiceProvider rsaPrivateKey)
        {

            // Create instance of AesManaged for
            // symetric decryption of the data.
            using (AesManaged aesManaged = new AesManaged())
            {
                aesManaged.KeySize = 256;
                aesManaged.BlockSize = 128;
                aesManaged.Mode = CipherMode.CBC;

                // Create byte arrays to get the length of
                // the encrypted key and IV.
                // These values were stored as 4 bytes each
                // at the beginning of the encrypted package.
                byte[] LenK = new byte[4];
                byte[] LenIV = new byte[4];

                // Consruct the file name for the decrypted file.
                string outFile = decrFolder + inFile.Substring(0, inFile.LastIndexOf(".")) + ".txt";

                // Use FileStream objects to read the encrypted
                // file (inFs) and save the decrypted file (outFs).
                using (FileStream inFs = new FileStream(encrFolder + inFile, FileMode.Open))
                {

                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Seek(0, SeekOrigin.Begin);
                    inFs.Read(LenK, 0, 3);
                    inFs.Seek(4, SeekOrigin.Begin);
                    inFs.Read(LenIV, 0, 3);

                    // Convert the lengths to integer values.
                    int lenK = BitConverter.ToInt32(LenK, 0);
                    int lenIV = BitConverter.ToInt32(LenIV, 0);

                    // Determine the start postition of
                    // the ciphter text (startC)
                    // and its length(lenC).
                    int startC = lenK + lenIV + 8;
                    int lenC = (int)inFs.Length - startC;

                    // Create the byte arrays for
                    // the encrypted AesManaged key,
                    // the IV, and the cipher text.
                    byte[] KeyEncrypted = new byte[lenK];
                    byte[] IV = new byte[lenIV];

                    // Extract the key and IV
                    // starting from index 8
                    // after the length values.
                    inFs.Seek(8, SeekOrigin.Begin);
                    inFs.Read(KeyEncrypted, 0, lenK);
                    inFs.Seek(8 + lenK, SeekOrigin.Begin);
                    inFs.Read(IV, 0, lenIV);
                    Directory.CreateDirectory(decrFolder);
                    // Use RSACryptoServiceProvider
                    // to decrypt the AesManaged key.
                    byte[] KeyDecrypted = rsaPrivateKey.Decrypt(KeyEncrypted, false);

                    // Decrypt the key.
                    using (ICryptoTransform transform = aesManaged.CreateDecryptor(KeyDecrypted, IV))
                    {

                        // Decrypt the cipher text from
                        // from the FileSteam of the encrypted
                        // file (inFs) into the FileStream
                        // for the decrypted file (outFs).
                        using (FileStream outFs = new FileStream(outFile, FileMode.Create))
                        {

                            int count = 0;
                            int offset = 0;

                            int blockSizeBytes = aesManaged.BlockSize / 8;
                            byte[] data = new byte[blockSizeBytes];

                            // By decrypting a chunk a time,
                            // you can save memory and
                            // accommodate large files.

                            // Start at the beginning
                            // of the cipher text.
                            inFs.Seek(startC, SeekOrigin.Begin);
                            using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                            {
                                do
                                {
                                    count = inFs.Read(data, 0, blockSizeBytes);
                                    offset += count;
                                    outStreamDecrypted.Write(data, 0, count);

                                }
                                while (count > 0);

                                outStreamDecrypted.FlushFinalBlock();
                                outStreamDecrypted.Close();
                            }
                            outFs.Close();
                        }
                        inFs.Close();
                    }

                }

            }
        }

    }
}