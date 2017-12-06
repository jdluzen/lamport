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
            var key = Lamport.GeneratePrivateKey();
            var pub = Lamport.GetPublicKey(key.PrivateKey);
            var plaintext = UTF8Encoding.UTF8.GetBytes("hello lamport world!");
            var sig = Lamport.Sign(plaintext, key.PrivateKey);
            bool verified = Lamport.Verify(plaintext, pub, sig);
            Assert.True(verified);

            var modplaintext = UTF8Encoding.UTF8.GetBytes("Hello lamport world!");
            bool modverified = Lamport.Verify(modplaintext, pub, sig);
            Assert.False(modverified);
        }

        [Fact]
        public void TestVerify16Sig()
        {
            var key = Lamport16.GeneratePrivateKey16();
            var pub = Lamport16.GetPublicKey16(key.PrivateKey);
            var plaintext = UTF8Encoding.UTF8.GetBytes("hello lamport world!");
            var sig = Lamport16.Sign16(plaintext, key.PrivateKey);
            bool verified = Lamport16.Verify16(plaintext, pub, sig);
            Assert.True(verified);

            var modplaintext = UTF8Encoding.UTF8.GetBytes("Hello lamport world!");
            bool modverified = Lamport16.Verify16(modplaintext, pub, sig);
            Assert.False(modverified);
        }
    }
}
