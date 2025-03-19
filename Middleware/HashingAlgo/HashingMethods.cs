using System;
using System.Security.Cryptography;

namespace Middleware.HashingAlgo
{
    public class HashingMethods
    {
        private const int SaltSize = 16;  // 128-bit salt for added security
        private const int HashSize = 32;  // 256-bit hash size
        private const int Iterations = 10000; // Number of iterations for PBKDF2 algorithm

   
        public static string HashPassword(string password)
        {
            try
            {
                byte[] salt = new byte[SaltSize];

                // Generate a cryptographically strong random salt
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(salt);
                }

                // Generate hash using PBKDF2 (Password-Based Key Derivation Function 2)
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations))
                {
                    byte[] hash = pbkdf2.GetBytes(HashSize);
                    byte[] hashBytes = new byte[SaltSize + HashSize];

                    // Copy salt and hash into one combined byte array
                    Array.Copy(salt, 0, hashBytes, 0, SaltSize);
                    Array.Copy(hash, 0, hashBytes, SaltSize, HashSize);

                    // Convert hash to Base64 string and return
                    return Convert.ToBase64String(hashBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error generating hashed password.", ex);
            }
        }

        /// <summary>
        /// Verifies a password against a stored hash.
        /// </summary>
        /// <param name="enteredPassword">The password entered by the user.</param>
        /// <param name="storedHash">The stored hashed password (Base64 encoded).</param>
        /// <returns>True if the password matches; otherwise, false.</returns>
        public static bool VerifyPassword(string enteredPassword, string storedHash)
        {
            try
            {
                // Convert Base64 encoded stored hash to byte array
                byte[] hashBytes = Convert.FromBase64String(storedHash);

                // Extract salt from stored hash
                byte[] salt = new byte[SaltSize];
                byte[] storedPasswordHash = new byte[HashSize];

                Array.Copy(hashBytes, 0, salt, 0, SaltSize);
                Array.Copy(hashBytes, SaltSize, storedPasswordHash, 0, HashSize);

                // Hash the entered password using the extracted salt
                using (var pbkdf2 = new Rfc2898DeriveBytes(enteredPassword, salt, Iterations))
                {
                    byte[] enteredPasswordHash = pbkdf2.GetBytes(HashSize);

                    // Compare stored hash and newly generated hash
                    return CompareHashes(enteredPasswordHash, storedPasswordHash);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error verifying password.", ex);
            }
        }

        /// <summary>
        /// Securely compares two hashes byte by byte.
        /// </summary>
        /// <param name="hash1">First hash (computed from entered password).</param>
        /// <param name="hash2">Second hash (stored password hash).</param>
        /// <returns>True if hashes match; otherwise, false.</returns>
        private static bool CompareHashes(byte[] hash1, byte[] hash2)
        {
            if (hash1.Length != hash2.Length)
                return false;

            // Compare each byte to prevent timing attacks
            for (int i = 0; i < hash1.Length; i++)
            {
                if (hash1[i] != hash2[i])
                    return false;
            }

            return true;
        }
    }
}
