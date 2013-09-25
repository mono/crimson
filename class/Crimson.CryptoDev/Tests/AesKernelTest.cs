//
// Author: 
//	Sebastien Pouliot  <sebastien@gmail.com>
// 
// Copyright 2012 Symform Inc.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Security.Cryptography;

using Crimson.Security.Cryptography;
using Crimson.Test.Base;

using NUnit.Framework;

namespace Crimson.Test.CryptoDev {

	[TestFixture]
	public class AesKernelTest : AesTest {
		
		[SetUp]
		protected void SetUp () 
		{
			CryptoDevTest.EnsureAvailability (Crimson.CryptoDev.Cipher.AES_CBC);
			algo = Create (); // shared
		}

		protected override SymmetricAlgorithm Create ()
		{
			return new AesKernel ();
		}

		static bool TestBlockSize (SymmetricAlgorithm cipher, int keySize, int dataSize)
		{
			RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider ();
			byte[] key = new byte [keySize];
			rng.GetBytes (key);
			byte[] iv = new byte [16]; // empty - not used for ECB
			byte[] input = new byte [dataSize];
			rng.GetBytes (input);
			return Test (cipher, key, iv, input, null);
		}

		static bool Test (SymmetricAlgorithm cipher, byte[] key, byte[] iv, byte[] input, byte[] expected)
		{
			cipher.Mode = CipherMode.ECB;
			cipher.KeySize = key.Length * 8;
			cipher.Padding = PaddingMode.Zeros;

			byte[] output = new byte [input.Length];
			ICryptoTransform encryptor = cipher.CreateEncryptor (key, iv);
			encryptor.TransformBlock (input, 0, input.Length, output, 0);
			if (expected != null && !Compare (output, expected))
				return false;
	
			byte[] original = new byte [output.Length];
			ICryptoTransform decryptor = cipher.CreateDecryptor (key, iv); 
			decryptor.TransformBlock (output, 0, output.Length, original, 0);
			return Compare (original, input);
		}

		static bool Compare (byte[] actual, byte[] expected)
		{
			if (actual == null)
				return (expected == null);
			if (expected == null)
				return false;
			if (actual.Length != expected.Length)
				return false;
			for (int i=0; i < actual.Length; i++) {
				if (actual [i] != expected [i])
					return false;
			}
			return true;
		}

		// mv_cesa has an hardware buffer limit (and the driver does not do the looping)
		[Test]
		public void MvCesaLimit ()
		{
			// max mv_cesa size
			Assert.IsTrue (TestBlockSize (algo, 16, 1936), "128-1936");
			Assert.IsTrue (TestBlockSize (algo, 24, 1936), "192-1936");
			Assert.IsTrue (TestBlockSize (algo, 32, 1936), "256-1936");
			// over the mv_cesa limit, works only if
			// (a) mv_cesa is not used (or fixed); or
			// (b) BufferBlockSize is set to 1936 or lower
			Assert.IsTrue (TestBlockSize (algo, 16, 1952), "128-1952");
			Assert.IsTrue (TestBlockSize (algo, 24, 1952), "192-1952");
			Assert.IsTrue (TestBlockSize (algo, 32, 1952), "256-1952");
		}
	}
}
