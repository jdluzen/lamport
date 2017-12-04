using System.Security.Cryptography;

namespace DZen.Security.Cryptography
{
    public interface IHashChain
    {
        byte[] GetNextHash(byte[] input);
    }
}