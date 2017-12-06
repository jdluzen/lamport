using System;
using System.Text;
using DZen.Security.Cryptography;
using Xunit;

namespace DZen.Security.Cryptography.LamportTests
{
    public class VerifyTests
    {
        [Fact]
        public void TestVerify()
        {
            foreach (Lamport lamp in new Lamport[] { new Lamport(), new Lamport16() })
            {
                var key = lamp.GeneratePrivateKey();
                var pub = lamp.GetPublicKey(key.PrivateKey);
                var plaintext = UTF8Encoding.UTF8.GetBytes("hello lamport world!");
                var sig = lamp.Sign(plaintext, key.PrivateKey);
                bool verified = lamp.Verify(plaintext, pub, sig);
                Assert.True(verified);

                var modplaintext = UTF8Encoding.UTF8.GetBytes("Hello lamport world!");
                bool modverified = lamp.Verify(modplaintext, pub, sig);
                Assert.False(modverified);
            }
        }
    }
}
