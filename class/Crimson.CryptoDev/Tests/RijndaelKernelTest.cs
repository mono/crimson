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
using System.IO;
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
			CryptoDevTest.EnsureAvailability (Crimson.CryptoDev.Cipher.AES_CBC);
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

		private static byte[] key1 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
		private static byte[] key2 = { 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01 };
		private static byte[] key3 = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

		public void AssertEquals (string msg, byte[] array1, byte[] array2) 
		{
			Assert.AreEqual (array1, array2, msg);
		}

		protected byte[] CombineKeys (byte[] key1, byte[] key2, byte[] key3) 
		{
			int k1l = key1.Length;
			int k2l = key2.Length;
			int k3l = key3.Length;
			byte[] key = new byte [k1l + k2l + k3l];
			Array.Copy (key1, 0, key, 0, k1l);
			Array.Copy (key2, 0, key, k1l, k2l);
			Array.Copy (key3, 0, key, k1l + k2l, k3l);
			return key;
		}

		private Rijndael GetAES () 
		{
			Rijndael aes = (Rijndael) Create ();
			aes.Key = CombineKeys (key1, key2, key3);
			return aes;
		}

		private byte[] GetData (byte size) 
		{
			byte[] data = new byte [size];
			for (byte i=0; i < size; i++) {
				data [i] = i;
			}
			return data;
		}

		private byte[] Decrypt (SymmetricAlgorithm algo, PaddingMode padding, byte[] data) 
		{
			algo.IV = new byte [algo.BlockSize >> 3];
			algo.Mode = CipherMode.CBC;
			algo.Padding = padding;
			ICryptoTransform ct = algo.CreateDecryptor ();
			return ct.TransformFinalBlock (data, 0, data.Length);
		}

		private byte[] Encrypt (SymmetricAlgorithm algo, PaddingMode padding, byte[] data) 
		{
			algo.IV = new byte [algo.BlockSize >> 3];
			algo.Mode = CipherMode.CBC;
			algo.Padding = padding;
			ICryptoTransform ct = algo.CreateEncryptor ();
			return ct.TransformFinalBlock (data, 0, data.Length);
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void RijndaelNone_SmallerThanOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (8);
			byte[] encdata = Encrypt (aes, PaddingMode.None, data);
		}

		[Test]
		public void RijndaelNone_ExactlyOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (16);
			byte[] encdata = Encrypt (aes, PaddingMode.None, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB", BitConverter.ToString (encdata), "RijndaelNone_ExactlyOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.None, encdata);
			AssertEquals ("RijndaelNone_ExactlyOneBlockSize_Decrypt", data, decdata);
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void RijndaelNone_MoreThanOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (20);
			byte[] encdata = Encrypt (aes, PaddingMode.None, data);
		}

		[Test]
		public void RijndaelNone_ExactMultipleBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (48);
			byte[] encdata = Encrypt (aes, PaddingMode.None, data);
			// note: encrypted data is truncated to a multiple of block size
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB-E1-27-3E-21-5A-BE-D5-12-F4-AF-06-8D-0A-BD-02-64-02-CB-FF-D7-32-19-5E-69-3C-54-C2-8C-A1-D7-72-FF", BitConverter.ToString (encdata), "RijndaelNone_ExactMultipleBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.None, encdata);
			AssertEquals ("RijndaelNone_ExactMultipleBlockSize_Decrypt", GetData (48), decdata);
		}

		[Test]
		public void RijndaelPKCS7_SmallerThanOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (8);
			byte[] encdata = Encrypt (aes, PaddingMode.PKCS7, data);
			Assert.AreEqual ("AB-E0-20-5E-BC-28-A0-B7-A7-56-A3-BF-13-55-13-7E", BitConverter.ToString (encdata), "RijndaelPKCS7_SmallerThanOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.PKCS7, encdata);
			AssertEquals ("RijndaelPKCS7_SmallerThanOneBlockSize_Decrypt", data, decdata);
		}

		[Test]
		public void RijndaelPKCS7_ExactlyOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (16);
			byte[] encdata = Encrypt (aes, PaddingMode.PKCS7, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB-60-CE-9F-E0-72-3B-D6-D1-A5-F8-33-D8-25-31-7F-D4", BitConverter.ToString (encdata), "RijndaelPKCS7_ExactlyOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.PKCS7, encdata);
			AssertEquals ("RijndaelPKCS7_ExactlyOneBlockSize_Decrypt", data, decdata);
		}

		[Test]
		public void RijndaelPKCS7_MoreThanOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (20);
			byte[] encdata = Encrypt (aes, PaddingMode.PKCS7, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB-06-3F-D3-51-8D-55-E9-2F-02-4A-4E-F2-91-55-31-83", BitConverter.ToString (encdata), "RijndaelPKCS7_MoreThanOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.PKCS7, encdata);
			AssertEquals ("RijndaelPKCS7_MoreThanOneBlockSize_Decrypt", data, decdata);
		}

		[Test]
		public void RijndaelPKCS7_ExactMultipleBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (48);
			byte[] encdata = Encrypt (aes, PaddingMode.PKCS7, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB-E1-27-3E-21-5A-BE-D5-12-F4-AF-06-8D-0A-BD-02-64-02-CB-FF-D7-32-19-5E-69-3C-54-C2-8C-A1-D7-72-FF-37-42-81-21-47-A7-E0-AA-64-A7-8B-65-25-95-AA-54", BitConverter.ToString (encdata), "RijndaelPKCS7_ExactMultipleBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.PKCS7, encdata);
			AssertEquals ("RijndaelPKCS7_ExactMultipleBlockSize_Decrypt", data, decdata);
		}
		
		[Test]
		public void RijndaelZeros_SmallerThanOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (8);
			byte[] encdata = Encrypt (aes, PaddingMode.Zeros, data);
			Assert.AreEqual ("DD-BE-D7-CE-E2-DD-5C-A3-3E-44-A1-76-00-E5-5B-5D", BitConverter.ToString (encdata), "RijndaelZeros_SmallerThanOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.Zeros, encdata);
			Assert.AreEqual ("00-01-02-03-04-05-06-07-00-00-00-00-00-00-00-00", BitConverter.ToString (decdata), "RijndaelZeros_SmallerThanOneBlockSize_Decrypt");
		}

		[Test]
		public void RijndaelZeros_ExactlyOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (16);
			byte[] encdata = Encrypt (aes, PaddingMode.Zeros, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB", BitConverter.ToString (encdata), "RijndaelZeros_ExactlyOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.Zeros, encdata);
			AssertEquals ("RijndaelZeros_ExactlyOneBlockSize_Decrypt", data, decdata);
		}

		[Test]
		public void RijndaelZeros_MoreThanOneBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (20);
			byte[] encdata = Encrypt (aes, PaddingMode.Zeros, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB-04-6C-F7-A5-DE-FF-B4-30-29-7A-0E-04-3B-D4-B8-F2", BitConverter.ToString (encdata), "RijndaelZeros_MoreThanOneBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.Zeros, encdata);
			Assert.AreEqual ("00-01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-00-00-00-00-00-00-00-00-00-00-00-00", BitConverter.ToString (decdata), "RijndaelZeros_MoreThanOneBlockSize_Decrypt");
		}

		[Test]
		public void RijndaelZeros_ExactMultipleBlockSize () 
		{
			Rijndael aes = GetAES ();
			byte[] data = GetData (48);
			byte[] encdata = Encrypt (aes, PaddingMode.Zeros, data);
			Assert.AreEqual ("79-42-36-2F-D6-DB-F1-0C-87-99-58-06-D5-F6-B0-BB-E1-27-3E-21-5A-BE-D5-12-F4-AF-06-8D-0A-BD-02-64-02-CB-FF-D7-32-19-5E-69-3C-54-C2-8C-A1-D7-72-FF", BitConverter.ToString (encdata), "RijndaelZeros_ExactMultipleBlockSize_Encrypt");
			byte[] decdata = Decrypt (aes, PaddingMode.Zeros, encdata);
			AssertEquals ("RijndaelZeros_ExactMultipleBlockSize_Decrypt", GetData (48), decdata);
		}

		private byte[] GetKey (SymmetricAlgorithm sa) 
		{
			byte[] key = new byte [sa.KeySize >> 3];
			// no weak key this way (DES, TripleDES)
			for (byte i=0; i < key.Length; i++)
				key [i] = i;
			return key;
		}

		private byte[] GetIV (SymmetricAlgorithm sa)
		{
			return new byte [sa.BlockSize >> 3];
		}

		private ICryptoTransform GetEncryptor (SymmetricAlgorithm sa, PaddingMode mode) 
		{
			sa.Mode = CipherMode.ECB; // basic (no) mode
			sa.Padding = mode;
			return sa.CreateEncryptor (GetKey (sa), GetIV (sa));
		}

		private ICryptoTransform GetDecryptor (SymmetricAlgorithm sa, PaddingMode mode)
		{
			sa.Mode = CipherMode.ECB; // basic (no) mode
			sa.Padding = mode;
			return sa.CreateDecryptor (GetKey (sa), GetIV (sa));
		}

		// the best way to verify padding is to:
		// a. encrypt data larger than one block with a padding mode "X"
		// b. decrypt the data with padding mode "None"
		// c. compare the last (padding) bytes with the expected padding

		private void ANSIX923_Full (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one full block
			byte[] data = new byte [bs]; // in bytes
			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.ANSIX923);
			byte[] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (data.Length * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte[] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - ANSI X.923 is all 0 except last byte (length)
			for (int i=0; i < bs - 1; i++)
				Assert.AreEqual (0x00, decdata [decdata.Length - pd + i], i.ToString ());
			Assert.AreEqual (pd, decdata [decdata.Length - 1], "last byte");
		}

		private void ANSIX923_Partial (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one and an half block
			byte[] data = new byte [bs + (bs >> 1)]; // in bytes
			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.ANSIX923);
			byte[] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (bs * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte[] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - ANSI X.923 is all 0 except last byte (length)
			for (int i = 0; i < pd - 1; i++)
				Assert.AreEqual (0x00, decdata [decdata.Length - pd + i], i.ToString ());
			Assert.AreEqual (pd, decdata [decdata.Length - 1], "last byte");
		}

		private void ISO10126_Full (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one full block
			byte [] data = new byte [bs]; // in bytes
			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.ISO10126);
			byte [] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (data.Length * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte [] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - ISO10126 is all random except last byte (length)
			Assert.AreEqual (pd, decdata [decdata.Length - 1], "last byte");
		}

		private void ISO10126_Partial (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one and an half block
			byte [] data = new byte [bs + (bs >> 1)]; // in bytes
			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.ISO10126);
			byte [] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (bs * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte [] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - ISO10126 is all random except last byte (length)
			Assert.AreEqual (pd, decdata [decdata.Length - 1], "last byte");
		}

		private void PKCS7_Full (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one full block
			byte[] data = new byte [bs]; // in bytes
			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.PKCS7);
			byte[] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (data.Length * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte[] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - PKCS7 is all padding char
			for (int i = 0; i < bs; i++)
				Assert.AreEqual (pd, decdata [decdata.Length - pd + i], i.ToString ());
		}

		private void PKCS7_Partial (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one and an half block
			byte[] data = new byte[bs + (bs >> 1)]; // in bytes
			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.PKCS7);
			byte[] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (bs * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte[] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - PKCS7 is all padding char
			for (int i = 0; i < pd; i++)
				Assert.AreEqual (pd, decdata [decdata.Length - pd + i], i.ToString ());
		}

		private void Zeros_Full (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one full block
			byte [] data = new byte [bs]; // in bytes
			for (int i = 0; i < data.Length; i++)
				data [i] = 0xFF;

			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.Zeros);
			byte [] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// NO extra block is used for zero padding
			Assert.AreEqual (data.Length, encdata.Length, "no extra block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte [] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			// now validate absence of padding
			Assert.AreEqual (0xFF, decdata [decdata.Length - 1], "no padding");
		}

		private void Zeros_Partial (SymmetricAlgorithm sa)
		{
			int bs = (sa.BlockSize >> 3);
			// one and an half block
			byte [] data = new byte [bs + (bs >> 1)]; // in bytes
			for (int i=0; i < data.Length; i++)
				data [i] = 0xFF;

			ICryptoTransform enc = GetEncryptor (sa, PaddingMode.Zeros);
			byte [] encdata = enc.TransformFinalBlock (data, 0, data.Length);
			// one block of padding is added			
			Assert.AreEqual (bs * 2, encdata.Length, "one more block added");

			ICryptoTransform dec = GetDecryptor (sa, PaddingMode.None);
			byte [] decdata = dec.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.AreEqual (encdata.Length, decdata.Length, "no unpadding");

			int pd = decdata.Length - data.Length;
			// now validate padding - Zeros is all 0x00 char
			for (int i = 0; i < pd; i++)
				Assert.AreEqual (0x00, decdata [decdata.Length - pd + i], i.ToString ());
		}

		[Test]
		public void Rijndael_ANSIX923_Full () 
		{
			ANSIX923_Full (Create ());
		}

		[Test]
		public void Rijndael_ANSIX923_Partial ()
		{
			ANSIX923_Partial (Create ());
		}

		[Test]
		public void Rijndael_ISO10126_Full ()
		{
			ISO10126_Full (Create ());
		}

		[Test]
		public void Rijndael_ISO10126_Partial ()
		{
			ISO10126_Partial (Create ());
		}

		[Test]
		public void Rijndael_PKCS7_Full ()
		{
			PKCS7_Full (Create ());
		}

		[Test]
		public void Rijndael_PKCS7_Partial ()
		{
			PKCS7_Partial (Create ());
		}

		[Test]
		public void Rijndael_Zeros_Full ()
		{
			Zeros_Full (Create ());
		}

		[Test]
		public void Rijndael_Zeros_Partial ()
		{
			Zeros_Partial (Create ());
		}
	}
}
