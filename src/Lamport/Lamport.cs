using System;
using System.Security.Cryptography;

namespace DZen.Security.Cryptography
{
    public class Lamport
    {
        public virtual (byte[] PrivateKey, (byte[] A, byte[] B)[] PrivateKeyPairs) GeneratePrivateKey(IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            byte[] privateKey = new byte[32];
            RandomNumberGenerator.Create().GetBytes(privateKey);
            return (privateKey, ExpandPrivateKey(privateKey));
        }

        public virtual (byte[] A, byte[] B)[] ExpandPrivateKey(byte[] privateKey, IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            (byte[] a, byte[] b)[] privateKeyPairs = new(byte[], byte[])[privateKey.Length];
            byte[] currentKey = privateKey;
            for (byte i = 0; i < privateKey.Length; i++)
            {
                byte[] a = hashChain.GetNextHash(currentKey);
                byte[] b = hashChain.GetNextHash(a);
                currentKey = b;
                privateKeyPairs[i] = (a, b);
            }
            return privateKeyPairs;
        }

        public virtual (byte[] Pa, byte[] Pb)[] GetPublicKey(byte[] privateKey, IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            (byte[] A, byte[] B)[] privateKeyExpanded = ExpandPrivateKey(privateKey);
            (byte[] pa, byte[] pb)[] publicKey = new(byte[], byte[])[privateKey.Length];
            for (byte i = 0; i < privateKey.Length; i++)
            {
                publicKey[i].pa = privateKeyExpanded[i].A;
                publicKey[i].pb = privateKeyExpanded[i].B;
                for (short j = 0; j < byte.MaxValue + 3; j++)
                {
                    publicKey[i].pa = hashChain.GetNextHash(publicKey[i].pa);
                    publicKey[i].pb = hashChain.GetNextHash(publicKey[i].pb);
                }
            }
            return publicKey;
        }

        public virtual (byte[] a, byte[] b)[] Sign(byte[] data, byte[] privateKey, IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            var privateKeyChunks = ExpandPrivateKey(privateKey);
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(data);
            (byte[] a, byte[] b)[] signature = new(byte[] ah, byte[] bh)[hash.Length];
            for (byte i = 0; i < hash.Length; i++)
            {
                byte[] a = privateKeyChunks[i].A;
                for (short j = 0; j < hash[i] + 1; j++)
                {
                    a = sha256.ComputeHash(a);
                }
                byte[] b = privateKeyChunks[i].B;
                for (short j = 0; j < (byte.MaxValue + 1) - hash[i]; j++)
                {
                    b = sha256.ComputeHash(b);
                }
                signature[i] = (a, b);
            }
            return signature;
        }

        public virtual bool Verify(byte[] data, (byte[] Pa, byte[] Pb)[] publicKey, (byte[] a, byte[] b)[] signature)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(data);
            for (byte i = 0; i < hash.Length; i++)
            {
                short i_a = 0, i_b = 0;
                byte[] a = signature[i].a;
                for (; i_a < byte.MaxValue + 1; i_a++)
                {
                    a = sha256.ComputeHash(a);
                    if (Memcmp(a, publicKey[i].Pa))
                        break;
                }
                if (i_a == byte.MaxValue + 1)
                    return false;
                byte[] b = signature[i].b;
                for (; i_b < byte.MaxValue + 1; i_b++)
                {
                    b = sha256.ComputeHash(b);
                    if (Memcmp(b, publicKey[i].Pb))
                        break;
                }
                if ((byte.MaxValue + 1) - i_a != i_b - 1 || (byte.MaxValue + 1) - i_a != hash[i])
                    return false;
            }
            return true;
        }

        protected static bool Memcmp(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }
    }
}