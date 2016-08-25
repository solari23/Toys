using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace CredentialManager
{
    /// <summary>
    /// Provides an interface for accruing, storing and handling credentials required at runtime. This class
    /// utilizes Windows DPAPI to persist credentials on disk such that they are only accessible in the
    /// context of the user who was logged in when the credentials were persisted.
    /// </summary>
    public sealed class CredentialManager : IDisposable
    {
        /// <summary>
        /// Gets the path to the credential database file.
        /// </summary>
        public string CredentialDatabaseFilePath { get; private set; }

        /// <summary>
        /// Gets whether or not the persisted credential database is loaded.
        /// </summary>
        public bool IsLoaded { get; private set; } = false;

        /// <summary>
        /// The underlying credentials database. This is a map of credential name -> credential.
        /// </summary>
        private Dictionary<string, SecureString> Credentials { get; set; } = new Dictionary<string, SecureString>();

        /// <summary>
        /// Constructor for the CredentialManager class.
        /// </summary>
        /// <param name="credentialDatabaseFilePath">The path to where the file where the credential database is/should be persisted.</param>
        public CredentialManager(string credentialDatabaseFilePath)
        {
            if (string.IsNullOrWhiteSpace(credentialDatabaseFilePath))
            {
                throw new ArgumentException("Path to credential DB can't be null or empty!", nameof(credentialDatabaseFilePath));
            }

            CredentialDatabaseFilePath = credentialDatabaseFilePath;
        }

        /// <summary>
        /// Accrues a new credential from the Console.
        /// </summary>
        /// <param name="credentialName">The name of the new credential.</param>
        public void AccrueCredentialFromConsole(string credentialName)
        {
            if (string.IsNullOrWhiteSpace(credentialName))
            {
                throw new ArgumentException("Credential name can't be null or empty!", nameof(credentialName));
            }

            SecureString newCredential = new SecureString();

            while (true)
            {
                ConsoleKeyInfo keyInfo = Console.ReadKey(intercept: true);

                if (keyInfo.Key == ConsoleKey.Enter)
                {
                    break;
                }

                if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (newCredential.Length > 0)
                    {
                        newCredential.RemoveAt(newCredential.Length - 1);
                    }
                }
                else
                {
                    newCredential.AppendChar(keyInfo.KeyChar);
                }
            }

            newCredential.MakeReadOnly();
            Credentials[credentialName] = newCredential;
        }

        /// <summary>
        /// Disposes the CredentialManager, securely disposing any credentials stored within.
        /// </summary>
        public void Dispose()
        {
            // Securely dispose all credentials.
            //
            foreach (var credentialEntry in Credentials)
            {
                credentialEntry.Value.Dispose();
            }
        }

        /// <summary>
        /// Creates a token for the requested credential using the given token generator function.
        /// </summary>
        /// <param name="credentialName">The name of the credential to use.</param>
        /// <param name="tokenGeneratorFunction">A function that takes the raw credential and outputs a token as a string.</param>
        /// <returns>The token generated using the credential.</returns>
        public string GenerateTokenForCredential(string credentialName, Func<SecureString, string> tokenGeneratorFunction)
        {
            if (string.IsNullOrWhiteSpace(credentialName))
            {
                throw new ArgumentException("Credential name can't be null or empty!", nameof(credentialName));
            }

            if (tokenGeneratorFunction == null)
            {
                throw new ArgumentNullException(nameof(tokenGeneratorFunction));
            }

            if (!IsCredentialAvailable(credentialName))
            {
                throw new Exception(string.Format("No credential '{0}' exists.", credentialName));
            }

            return tokenGeneratorFunction(Credentials[credentialName]);
        }

        /// <summary>
        /// Checks whether or not a credential with the given name is available.
        /// </summary>
        /// <param name="credentialName">The name of the credential to check for.</param>
        /// <returns>True if a credential with the given name is available and false otherwise.</returns>
        public bool IsCredentialAvailable(string credentialName)
        {
            return string.IsNullOrWhiteSpace(credentialName) ? false : Credentials.ContainsKey(credentialName);
        }

        /// <summary>
        /// Loads the persisted credentials stored in the credential database file.
        /// </summary>
        public void LoadCredentialsDatabase()
        {
            if (IsLoaded)
            {
                throw new InvalidOperationException("Credentials are already loaded!");
            }

            try
            {
                using (FileStream fs = File.OpenRead(CredentialDatabaseFilePath))
                {
                    string credentialName;
                    SecureString credential;
                    while (TryReadCredential(fs, out credentialName, out credential))
                    {
                        Credentials[credentialName] = credential;
                    }
                }
            }
            catch (FileNotFoundException e)
            {
                // The credential database doesn't exist. Ignore the error.
            }

            IsLoaded = true;
        }

        /// <summary>
        /// Securely persists all credentials to the credential database file.
        /// </summary>
        public void SaveCredentialsToDatabase()
        {
            using (FileStream fs = File.OpenWrite(CredentialDatabaseFilePath))
            {
                foreach (var credentialPair in Credentials)
                {
                    // We need some secondary entropy for DPAPI.
                    //
                    byte[] secondaryEntropy = Guid.NewGuid().ToByteArray();

                    byte[] plaintextCredentialBlob = null;

                    try
                    {
                        byte[] credentialNameBytes = Encoding.Default.GetBytes(credentialPair.Key);

                        plaintextCredentialBlob = new byte[Encoding.Default.GetByteCount(credentialPair.Key) + credentialPair.Value.Length + 1];

                        // Copy the credential name into the plaintext blob.
                        //
                        for (int i = 0; i < credentialNameBytes.Length; i++)
                        {
                            plaintextCredentialBlob[i] = credentialNameBytes[i];
                        }

                        // Set the zero byte separating the credential name from the credential itself.
                        //
                        plaintextCredentialBlob[credentialNameBytes.Length] = 0;

                        // Copy the credential into the plaintext blob.
                        //
                        WriteSecureStringToBytes(credentialPair.Value, plaintextCredentialBlob, credentialNameBytes.Length + 1);

                        // Now encrypt the credential blob via DPAPI.
                        //
                        byte[] encryptedCredentialBlob = ProtectedData.Protect(plaintextCredentialBlob, secondaryEntropy, DataProtectionScope.CurrentUser);

                        // Don't need the plaintext bytes anymore.. get rid of them as soon as possible.
                        //
                        ZeroBytes(plaintextCredentialBlob);

                        // Write to the database:
                        //  - The secondary entropy
                        //  - The size of the encrypted blob (4 bytes)
                        //  - The encrypted blob
                        //
                        fs.Write(secondaryEntropy, 0, secondaryEntropy.Length);

                        int encryptedBlobSize = encryptedCredentialBlob.Length;
                        byte[] encryptedBlobSizeBytes = BitConverter.GetBytes(encryptedBlobSize);
                        Debug.Assert(encryptedBlobSizeBytes.Length == sizeof(int));
                        fs.Write(encryptedBlobSizeBytes, 0, sizeof(int));

                        fs.Write(encryptedCredentialBlob, 0, encryptedCredentialBlob.Length);

                        // We don't need the encyrpted bytes anymore.. just for funzies, get rid of them.
                        //
                        ZeroBytes(encryptedCredentialBlob);
                    }
                    finally
                    {
                        ZeroBytes(plaintextCredentialBlob);
                    }
                }

                fs.Close();
            }
        }

        #region Private Helpers

        /// <summary>
        /// Gets the index of the first zero byte in the given byte array.
        /// </summary>
        /// <param name="bytes">The byte array to search in.</param>
        /// <returns>The index of the first zero byte, or -1 if not found.</returns>
        private static int GetIndexOfFirstZeroByte(byte[] bytes)
        {
            int index = -1;

            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    if (bytes[i] == 0)
                    {
                        index = i;
                        break;
                    }
                }
            }

            return index;
        }

        /// <summary>
        /// Reads a SecureString from an array of bytes.
        /// </summary>
        /// <param name="bytes">The byte array from which to retrieve the SecureString.</param>
        /// <param name="offset">The offset index from which to start reading the SecureString.</param>
        /// <param name="count">The number of characters to read into the SecureString.</param>
        /// <returns>The SecureString read from the byte array.</returns>
        private static SecureString ReadSecureStringFromBytes(byte[] bytes, int offset, int count)
        {
            SecureString secureString = new SecureString();
            
            if (bytes != null && (offset + count <= bytes.Length))
            {
                int upperBound = offset + count;
                for (int i = offset; i < upperBound; i++)
                {
                    secureString.AppendChar((char)bytes[i]);
                }
            }

            secureString.MakeReadOnly();
            return secureString;
        }

        /// <summary>
        /// Writes a SecureString to an array of bytes.
        /// </summary>
        /// <remarks>
        /// Caller should clear the byte array as soon as they're done with it!
        /// </remarks>
        /// <param name="secureString">The SecureString to write.</param>
        /// <param name="bytes">The byte array to write the SecureString to.</param>
        /// <param name="offset">The offset from which to start writing.</param>
        private static void WriteSecureStringToBytes(SecureString secureString, byte[] bytes, int offset)
        {
            if (bytes != null && offset + secureString.Length <= bytes.Length)
            {
                IntPtr ptr = Marshal.SecureStringToGlobalAllocAnsi(secureString);

                if (ptr != IntPtr.Zero)
                {
                    Marshal.Copy(ptr, bytes, offset, secureString.Length);
                    Marshal.ZeroFreeGlobalAllocAnsi(ptr);
                }
            }
        }

        /// <summary>
        /// Attempts to read a credential from the FileStream.
        /// </summary>
        /// <param name="fs">The FileStream to read from.</param>
        /// <param name="credentialName">The name of the credential read.</param>
        /// <param name="credential">The credential read.</param>
        /// <returns>True if credential was read successfully, false otherwise.</returns>
        private static bool TryReadCredential(FileStream fs, out string credentialName, out SecureString credential)
        {
            const int BYTES_PER_GUID = 16;

            credentialName = string.Empty;
            credential = new SecureString();

            // Read the GUID used as secondary entropy for DPAPI.
            //
            byte[] secondaryEntropy = new byte[BYTES_PER_GUID];
            if (fs.Read(secondaryEntropy, 0, BYTES_PER_GUID) != BYTES_PER_GUID)
            {
                credential.MakeReadOnly();
                return false;
            }

            // Read the size of the encrypted credential blob.
            //
            byte[] blobSizeBytes = new byte[sizeof(int)];
            if (fs.Read(blobSizeBytes, 0, sizeof(int)) != sizeof(int))
            {
                credential.MakeReadOnly();
                return false;
            }

            int blobSize = BitConverter.ToInt32(blobSizeBytes, 0);
            if (blobSize <= 0)
            {
                credential.MakeReadOnly();
                return false;
            }

            // Read the encrypted credential blob.
            //
            byte[] encryptedCredentialBlob = new byte[blobSize];
            if (fs.Read(encryptedCredentialBlob, 0, blobSize) != blobSize)
            {
                credential.MakeReadOnly();
                return false;
            }

            // Let DPAPI decrypt the blob.
            //
            byte[] plaintextCredentialBlob = null;
            try
            {
                plaintextCredentialBlob = ProtectedData.Unprotect(encryptedCredentialBlob, secondaryEntropy, DataProtectionScope.CurrentUser);

                // We don't need the encyrpted bytes anymore.. just for funzies, get rid of them.
                //
                ZeroBytes(encryptedCredentialBlob);

                // A zero byte separates the credential name and the credential itself.
                //
                int indexFirstZero = GetIndexOfFirstZeroByte(plaintextCredentialBlob);

                if (indexFirstZero != -1)
                {
                    credentialName = Encoding.Default.GetString(plaintextCredentialBlob, 0, indexFirstZero);
                    credential = ReadSecureStringFromBytes(plaintextCredentialBlob, indexFirstZero + 1, plaintextCredentialBlob.Length - indexFirstZero - 1);
                }
            }
            finally
            {
                ZeroBytes(plaintextCredentialBlob);
            }

            credential.MakeReadOnly();
            return true;
        }

        /// <summary>
        /// Zeroes all the bytes in the given byte array.
        /// </summary>
        /// <param name="bytes">They byte array to clear.</param>
        private static void ZeroBytes(byte[] bytes)
        {
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = 0;
                }
            }
        }

        #endregion
    }
}
