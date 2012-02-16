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
	public class RijndaelKernelTest : RijndaelTest {
		
		[SetUp]
		protected void SetUp () 
		{
			CryptoDevTest.EnsureAvailability ();
			algo = Create (); // shared
		}

		protected override SymmetricAlgorithm Create ()
		{
			return new RijndaelKernel ();
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

		[Test]
		public void CbcIvBlock ()
		{
			byte[] key = algo.Key;
			byte[] iv = algo.IV;
			algo.Mode = CipherMode.CBC;

			// 1952 = max mv_cesa + one block
			for (int i = 16; i <= 1952; i += 16) {
				byte[] data = new byte [i];
				byte[] enc1 = algo.CreateEncryptor ().TransformFinalBlock (data, 0, data.Length);
				byte[] enc2 = null;
				using (Rijndael r = new RijndaelManaged ()) {
					r.Mode = CipherMode.CBC;
					r.Key = key;
					r.IV = iv;
					enc2 = algo.CreateEncryptor ().TransformFinalBlock (data, 0, data.Length);
				}

				if (!Compare (enc1, enc2))
					Assert.Fail ("Data size = " + i);
			}
		}
	}
}
