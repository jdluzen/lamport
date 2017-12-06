using System;
using System.Security.Cryptography;

namespace DZen.Security.Cryptography
{
    public class Lamport16 : Lamport
    {
        public override (byte[] A, byte[] B)[] ExpandPrivateKey(byte[] privateKey, IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            (byte[] a, byte[] b)[] privateKeyPairs = new(byte[], byte[])[privateKey.Length / 2];
            byte[] currentKey = privateKey;
            for (byte i = 0; i < privateKeyPairs.Length; i++)
            {
                byte[] a = hashChain.GetNextHash(currentKey);
                byte[] b = hashChain.GetNextHash(a);
                currentKey = b;
                privateKeyPairs[i] = (a, b);
            }
            return privateKeyPairs;
        }

        public override (byte[] Pa, byte[] Pb)[] GetPublicKey(byte[] privateKey, IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            (byte[] A, byte[] B)[] privateKeyExpanded = ExpandPrivateKey(privateKey);
            (byte[] pa, byte[] pb)[] publicKey = new(byte[], byte[])[privateKeyExpanded.Length];
            for (byte i = 0; i < publicKey.Length; i++)
            {
                publicKey[i].pa = privateKeyExpanded[i].A;
                publicKey[i].pb = privateKeyExpanded[i].B;
                for (int j = 0; j < ushort.MaxValue + 3; j++)
                {
                    publicKey[i].pa = hashChain.GetNextHash(publicKey[i].pa);
                    publicKey[i].pb = hashChain.GetNextHash(publicKey[i].pb);
                }
            }
            return publicKey;
        }

        public override (byte[] a, byte[] b)[] Sign(byte[] data, byte[] privateKey, IHashChain hashChain = null)
        {
            if (hashChain == null)
                hashChain = new Sha256HashChain();
            var privateKeyChunks = ExpandPrivateKey(privateKey);
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(data);
            (byte[] a, byte[] b)[] signature = new(byte[] ah, byte[] bh)[privateKey.Length / 2];
            for (byte i = 0; i < hash.Length / 2; i++)
            {
                byte[] a = privateKeyChunks[i].A;
                ushort hashValue = BitConverter.ToUInt16(hash, i * 2);
                for (int j = 0; j < hashValue + 1; j++)
                {
                    a = sha256.ComputeHash(a);
                }
                byte[] b = privateKeyChunks[i].B;
                for (int j = 0; j < (ushort.MaxValue + 1) - hashValue; j++)
                {
                    b = sha256.ComputeHash(b);
                }
                signature[i] = (a, b);
            }
            return signature;
        }

        public override bool Verify(byte[] data, (byte[] Pa, byte[] Pb)[] publicKey, (byte[] a, byte[] b)[] signature)
        {
            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(data);
            for (byte i = 0; i < signature.Length; i++)
            {
                int i_a = 0, i_b = 0;
                byte[] a = signature[i].a;
                for (; i_a < ushort.MaxValue + 1; i_a++)
                {
                    a = sha256.ComputeHash(a);
                    if (Memcmp(a, publicKey[i].Pa))
                        break;
                }
                if (i_a == ushort.MaxValue + 1)
                    return false;
                byte[] b = signature[i].b;
                for (; i_b < ushort.MaxValue + 1; i_b++)
                {
                    b = sha256.ComputeHash(b);
                    if (Memcmp(b, publicKey[i].Pb))
                        break;
                }
                ushort hashValue = BitConverter.ToUInt16(hash, i * 2);
                if ((ushort.MaxValue + 1) - i_a != i_b - 1 || (ushort.MaxValue + 1) - i_a != hashValue)
                    return false;
            }
            return true;
        }
    }
}