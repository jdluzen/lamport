using System.Security.Cryptography;

namespace DZen.Security.Cryptography
{
    public class Sha256HashChain : IHashChain
    {
        private SHA256 hasher;
        internal SHA256 Hasher
        {
            get
            {
                return hasher ?? (hasher = SHA256.Create());
            }
        }
        public byte[] GetNextHash(byte[] input)
        {
            return Hasher.ComputeHash(input);
        }
    }
}