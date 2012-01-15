//
// RijndaelTest.cs - NUnit Test Cases for Rijndael
//
// Author:
//	Sebastien Pouliot (sebastien@ximian.com)
//
// (C) 2002 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004 Novell, Inc (http://www.novell.com)
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

using NUnit.Framework;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Crimson.Test.Base {

	public abstract class AesTest : SymmetricAlgorithmTest {
	
		[Test]
		public void DefaultProperties ()
		{
			Assert.AreEqual (128, algo.BlockSize, "BlockSize");
			Assert.AreEqual (128, algo.FeedbackSize, "FeedbackSize");
			Assert.AreEqual (256, algo.KeySize, "KeySize");
			Assert.AreEqual (CipherMode.CBC, algo.Mode, "Mode");
			Assert.AreEqual (PaddingMode.PKCS7, algo.Padding, "Padding");
			Assert.AreEqual (1, algo.LegalBlockSizes.Length, "LegalBlockSizes");
			// LegalBlockSizes varies between AES and Rijndeal
			if (algo is Rijndael) {
				Assert.AreEqual (256, algo.LegalBlockSizes [0].MaxSize, "LegalBlockSizes.MaxSize");
				Assert.AreEqual (128, algo.LegalBlockSizes [0].MinSize, "LegalBlockSizes.MinSize");
				Assert.AreEqual (64, algo.LegalBlockSizes [0].SkipSize, "LegalBlockSizes.SkipSize");
			} else {
				Assert.AreEqual (128, algo.LegalBlockSizes [0].MaxSize, "LegalBlockSizes.MaxSize");
				Assert.AreEqual (128, algo.LegalBlockSizes [0].MinSize, "LegalBlockSizes.MinSize");
				Assert.AreEqual (0, algo.LegalBlockSizes [0].SkipSize, "LegalBlockSizes.SkipSize");
			}
			Assert.AreEqual (1, algo.LegalKeySizes.Length, "LegalKeySizes");
			Assert.AreEqual (256, algo.LegalKeySizes [0].MaxSize, "LegalKeySizes.MaxSize");
			Assert.AreEqual (128, algo.LegalKeySizes [0].MinSize, "LegalKeySizes.MinSize");
			Assert.AreEqual (64, algo.LegalKeySizes [0].SkipSize, "LegalKeySizes.SkipSize");
		}

		// FIPS197 B 
		public void TestFIPS197_AppendixB () 
		{
			byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
			byte[] iv = new byte[16]; // empty - not used for ECB
			byte[] input = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
			byte[] expected = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

			algo.Mode = CipherMode.ECB;
			algo.KeySize = 128;
			algo.Padding = PaddingMode.Zeros;

			byte[] output = new byte [input.Length];
			ICryptoTransform encryptor = algo.CreateEncryptor (key, iv);
			encryptor.TransformBlock (input, 0, input.Length, output, 0);
			Assert.AreEqual (expected, output, "FIPS197 B Encrypt");
	
			byte[] original = new byte [output.Length];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv); 
			decryptor.TransformBlock (output, 0, output.Length, original, 0);
			Assert.AreEqual (input, original, "FIPS197 B Decrypt");
		}

		// FIPS197 C.1 AES-128 (Nk=4, Nr=10)
		public void TestFIPS197_AppendixC1 () 
		{
			byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
			byte[] iv = new byte[16]; // empty - not used for ECB
			byte[] input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
			byte[] expected = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };

			algo.Mode = CipherMode.ECB;
			algo.KeySize = 128;
			algo.Padding = PaddingMode.Zeros;

			byte[] output = new byte [input.Length];
			ICryptoTransform encryptor = algo.CreateEncryptor (key, iv);
			encryptor.TransformBlock(input, 0, input.Length, output, 0);
			Assert.AreEqual (expected, output, "FIPS197 C1 Encrypt");
	
			byte[] original = new byte [output.Length];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv); 
			decryptor.TransformBlock(output, 0, output.Length, original, 0);
			Assert.AreEqual (input, original, "FIPS197 C1 Decrypt");
		}

		// FIPS197 C.2 AES-192 (Nk=6, Nr=12)
		public void TestFIPS197_AppendixC2 () 
		{
			byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
			byte[] iv = new byte[16]; // empty - not used for ECB
			byte[] input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
			byte[] expected = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

			algo.Mode = CipherMode.ECB;
			algo.KeySize = 192;
			algo.Padding = PaddingMode.Zeros;

			byte[] output = new byte [input.Length];
			ICryptoTransform encryptor = algo.CreateEncryptor (key, iv);
			encryptor.TransformBlock(input, 0, input.Length, output, 0);
			Assert.AreEqual (expected, output, "FIPS197 C2 Encrypt");
	
			byte[] original = new byte [output.Length];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv); 
			decryptor.TransformBlock(output, 0, output.Length, original, 0);
			Assert.AreEqual (input, original, "FIPS197 C2 Decrypt");
		}

		// C.3 AES-256 (Nk=8, Nr=14)
		public void TestFIPS197_AppendixC3 () 
		{
			byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
			byte[] iv = new byte[16]; // empty - not used for ECB
			byte[] input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
			byte[] expected = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

			algo.Mode = CipherMode.ECB;
			algo.KeySize = 256;
			algo.Padding = PaddingMode.Zeros;

			byte[] output = new byte [input.Length];
			ICryptoTransform encryptor = algo.CreateEncryptor (key, iv);
			encryptor.TransformBlock(input, 0, input.Length, output, 0);
			Assert.AreEqual (expected, output, "FIPS197 C3 Encrypt");
	
			byte[] original = new byte [output.Length];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv); 
			decryptor.TransformBlock(output, 0, output.Length, original, 0);
			Assert.AreEqual (input, original, "FIPS197 C3 Decrypt");
		}

		[Test]
		public void ChangingKeySize ()
		{
			byte[] original_iv = algo.IV;
			foreach (KeySizes ks in algo.LegalKeySizes) {
				for (int key_size = ks.MinSize; key_size <= ks.MaxSize; key_size += ks.SkipSize) {
					algo.KeySize = key_size;
					string s = key_size.ToString ();
					// key is updated
					Assert.AreEqual ((key_size >> 3), algo.Key.Length, s + ".Key.Length");
					// iv isn't
					Assert.AreEqual (original_iv, algo.IV, s + ".IV");
				}
			}
		}

		[Test]
		public void ChangingBlockSize ()
		{
			byte[] original_key = algo.Key;
			foreach (KeySizes bs in algo.LegalBlockSizes) {
				for (int block_size = bs.MinSize; block_size <= bs.MaxSize; block_size += bs.SkipSize) {
					algo.BlockSize = block_size;
					string s = block_size.ToString ();
					// key isn't updated
					Assert.AreEqual (original_key, algo.Key, s + ".Key");
					// iv is updated
					Assert.AreEqual ((block_size >> 3), algo.IV.Length, s + ".IV.Length");
					// don't endlessly loop for AES
					if (bs.SkipSize == 0)
						break;
				}
			}
		}

		public void CheckCBC(ICryptoTransform encryptor, ICryptoTransform decryptor, 
					   byte[] plaintext, byte[] expected) 
		{
	
			if ((plaintext.Length % encryptor.InputBlockSize) != 0) {
				throw new ArgumentException("Must have complete blocks");
			}
	
			byte[] ciphertext = new byte[plaintext.Length];
			for (int i=0; i < plaintext.Length; i += encryptor.InputBlockSize) {
				encryptor.TransformBlock(plaintext, i, encryptor.InputBlockSize, ciphertext, i);
			}
			Assert.AreEqual (expected, ciphertext, "CBC");
	
			byte[] roundtrip = new byte[plaintext.Length];
			for (int i=0; i < ciphertext.Length; i += decryptor.InputBlockSize) {
				decryptor.TransformBlock(ciphertext, i, decryptor.InputBlockSize, roundtrip, i);
			}
			Assert.AreEqual (plaintext, roundtrip, "CBC-rt");
		}

		[Test]
		public void CBC_0() {
	
			byte[] plaintext = new byte[32];
			for (int i=0; i < plaintext.Length; i++) plaintext[i] = 0;
	
			byte[] iv = new byte[16];
			for (byte i=0; i < iv.Length; i++) {
				iv[i] = 0;
			}
	
			SymmetricAlgorithm aes = Create ();
			byte[] key = new byte[16];	
	
			for (int i=0; i < 16; i++) key[i] = 0;
			aes.Key = key;
			aes.BlockSize = 128;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.Zeros;
			aes.Key = key;
	
			byte[] expected = { 
				0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 
				0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e, 
				0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7, 
				0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9, 0x8d, 0xbc };
	
			CheckCBC (aes.CreateEncryptor (key, iv), aes.CreateDecryptor (key, iv), plaintext, expected);
		}

		[Test]
		public void CBC_1 ()
		{
			byte[] plaintext = new byte[32];
			for (int i=0; i < plaintext.Length; i++) plaintext[i] = 0;
	
			byte[] iv = new byte[16];
			for (byte i=0; i < iv.Length; i++) {
				iv[i] = i;
			}
	
			SymmetricAlgorithm aes = Create ();
			byte[] key = new byte[16];
			for (byte i=0; i < 16; i++) key[i] = 0;

			aes.Key = key;
			aes.BlockSize = 128;
			aes.Mode = CipherMode.CBC;
			aes.Padding = PaddingMode.Zeros;
	
			byte[] expected = { 
				0x7a, 0xca, 0x0f, 0xd9, 0xbc, 0xd6, 0xec, 0x7c, 
				0x9f, 0x97, 0x46, 0x66, 0x16, 0xe6, 0xa2, 0x82, 
				0x66, 0xc5, 0x84, 0x17, 0x1d, 0x3c, 0x20, 0x53, 
				0x6f, 0x0a, 0x09, 0xdc, 0x4d, 0x1e, 0x45, 0x3b };
	
			CheckCBC (aes.CreateEncryptor (key, iv), aes.CreateDecryptor (key, iv), plaintext, expected);
		}
	
		public void CheckECBRoundtrip(ICryptoTransform encryptor, ICryptoTransform decryptor, 
					   byte[] plaintext, byte[] expected)
		{
			byte[] ciphertext = new byte[plaintext.Length];
			encryptor.TransformBlock(plaintext, 0, plaintext.Length, ciphertext, 0);

			Assert.AreEqual (expected, ciphertext, "ECB");
	
			byte[] roundtrip = new byte[plaintext.Length];
			decryptor.TransformBlock(ciphertext, 0, ciphertext.Length, roundtrip, 0);

			Assert.AreEqual (plaintext, roundtrip, "ECB-rt-len");
		}

		[Test]
		public void ECB ()
		{
			byte[] plaintext = new byte[16];
			byte[] iv = new byte[16];
	
			for (int i=0; i < 16; i++) {
				plaintext[i] = (byte) (i*16 + i);
			}
	
			SymmetricAlgorithm aes = Create ();
			aes.Mode = CipherMode.ECB;
			aes.Padding = PaddingMode.Zeros;
	
			byte[] key16 = new byte[16];
			byte[] key24 = new byte[24];
			byte[] key32 = new byte[32];
	
			for (int i=0; i < 32; i++) {
				if (i < 16) key16[i] = (byte) i;
				if (i < 24) key24[i] = (byte) i;
				key32[i] = (byte) i;
			}
	
				
			byte[] exp16 = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
					 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
			byte[] exp24 = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
					 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
			byte[] exp32 = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
					 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 }; 
	
			aes.Key = key16;
			aes.KeySize = 128;	
			CheckECBRoundtrip(
				aes.CreateEncryptor (key16, iv), aes.CreateDecryptor (key16, iv), 
				plaintext, exp16
			);
	
			aes.Key = key24;
			aes.KeySize = 192;
			CheckECBRoundtrip(
				aes.CreateEncryptor (key24, iv), aes.CreateDecryptor (key24, iv), 
				plaintext, exp24
			);
	
			aes.Key = key32;
			aes.KeySize = 256;
			CheckECBRoundtrip(
				aes.CreateEncryptor (key32, iv), aes.CreateDecryptor (key32, iv), 
				plaintext, exp32
			);
		}

		protected void AssertEquals (string msg, byte[] expected, byte[] actual)
		{
			string s1 = BitConverter.ToString (expected);
			string s2 = BitConverter.ToString (actual);
			if (s1 != s2) {
				Console.WriteLine ("E: {0}", s1);
				Console.WriteLine ("A: {0}", s2);
			}
			Assert.AreEqual (expected, actual, msg);
		}

		protected void Encrypt (ICryptoTransform trans, byte[] input, byte[] output)
		{
			int bs = trans.InputBlockSize;
			int full = input.Length / bs;
			int partial = input.Length % bs;
			int pos = 0;
			for (int i=0; i < full; i++) {
				trans.TransformBlock (input, pos, bs, output, pos);
				pos += bs;
			}
			if (partial > 0) {
				byte[] final = trans.TransformFinalBlock (input, pos, partial);
				Array.Copy (final, 0, output, pos, bs);
			}
		}

		protected void Decrypt (ICryptoTransform trans, byte[] input, byte[] output)
		{
			int bs = trans.InputBlockSize;
			int full = input.Length / bs;
			int partial = input.Length % bs;
			int pos = 0;
			for (int i=0; i < full; i++) {
				trans.TransformBlock (input, pos, bs, output, pos);
				pos += bs;
			}
			if (partial > 0) {
				byte[] final = trans.TransformFinalBlock (input, pos, partial);
				Array.Copy (final, 0, output, pos, partial);
			}
		}

		protected abstract SymmetricAlgorithm Create ();

		[Test]
		public void k128b128_ECB_None ()
		{
			byte[] key = { 0xAF, 0x4D, 0xFE, 0x58, 0x33, 0xAC, 0x91, 0xB2, 0xFA, 0xA3, 0x96, 0x54, 0x0B, 0x68, 0xDD, 0xA1 };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0xAF, 0x70, 0xC2, 0x2E, 0x2D, 0xF1, 0x0D, 0x7F, 0x52, 0xF4, 0x65, 0x79, 0x78, 0xAC, 0x80, 0xEF };
			byte[] expected = { 0x6D, 0xC2, 0x4A, 0x51, 0x2D, 0xAB, 0x67, 0xCB, 0xD8, 0xD4, 0xD5, 0xE6, 0x0B, 0x24, 0x02, 0x90, 0x6D, 0xC2, 0x4A, 0x51, 0x2D, 0xAB, 0x67, 0xCB, 0xD8, 0xD4, 0xD5, 0xE6, 0x0B, 0x24, 0x02, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.None;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k128b128_ECB_None Encrypt", expected, output);

			// in ECB the first 2 blocks should be equals (as the IV is not used)
			byte[] block1 = new byte[blockLength];
			Array.Copy (output, 0, block1, 0, blockLength);
			byte[] block2 = new byte[blockLength];
			Array.Copy (output, blockLength, block2, 0, blockLength);
			AssertEquals ("k128b128_ECB_None b1==b2", block1, block2);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k128b128_ECB_None Decrypt", input, original);
		}

		[Test]
		public void k128b128_ECB_Zeros ()
		{
			byte[] key = { 0xA4, 0x39, 0x01, 0x00, 0xDB, 0x0A, 0x47, 0xD8, 0xD8, 0xDC, 0x01, 0xF4, 0xBE, 0x96, 0xF4, 0xBB };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0xEA, 0xBD, 0x55, 0x85, 0x3F, 0xC1, 0x5F, 0xCB, 0x06, 0x26, 0x3F, 0x88, 0x6A, 0x2D, 0x69, 0x45 };
			//byte[] expected = { 0x19, 0x32, 0x7E, 0x79, 0xE3, 0xC1, 0xFE, 0xA0, 0xFD, 0x26, 0x27, 0x61, 0xC0, 0xB8, 0x06, 0xC2, 0x19, 0x32, 0x7E, 0x79, 0xE3, 0xC1, 0xFE, 0xA0, 0xFD, 0x26, 0x27, 0x61, 0xC0, 0xB8, 0x06, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.Zeros;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			// some exception can be normal... other not so!
			try {
				Encrypt (encryptor, input, output);
			}
			catch (Exception e) {
				if (e.Message != "Input buffer contains insufficient data. ")
					Assert.Fail ("k128b128_ECB_Zeros: This isn't the expected exception: " + e.ToString ());
			}
		}

		[Test]
		public void k128b128_ECB_PKCS7 ()
		{
			byte[] key = { 0x5C, 0x58, 0x03, 0x1D, 0x05, 0x07, 0xDE, 0x93, 0x8D, 0x85, 0xFD, 0x50, 0x68, 0xA3, 0xD7, 0x6B };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0x1C, 0x32, 0xFE, 0x99, 0x95, 0x16, 0x74, 0xC0, 0x6F, 0xE6, 0x01, 0x2C, 0x1F, 0x07, 0x54, 0xE8 };
			byte[] expected = { 0xEE, 0x1C, 0x0B, 0x2F, 0x1E, 0xCE, 0x69, 0xBC, 0xEA, 0xF6, 0xED, 0xA9, 0xF0, 0xE3, 0xE7, 0xC3, 0xEE, 0x1C, 0x0B, 0x2F, 0x1E, 0xCE, 0x69, 0xBC, 0xEA, 0xF6, 0xED, 0xA9, 0xF0, 0xE3, 0xE7, 0xC3, 0x2E, 0xB4, 0x6F, 0x8C, 0xD3, 0x37, 0xF4, 0x8E, 0x6D, 0x08, 0x35, 0x47, 0xD1, 0x1A, 0xB2, 0xA0 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.PKCS7;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k128b128_ECB_PKCS7 Encrypt", expected, output);

			// in ECB the first 2 blocks should be equals (as the IV is not used)
			byte[] block1 = new byte[blockLength];
			Array.Copy (output, 0, block1, 0, blockLength);
			byte[] block2 = new byte[blockLength];
			Array.Copy (output, blockLength, block2, 0, blockLength);
			AssertEquals ("k128b128_ECB_PKCS7 b1==b2", block1, block2);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k128b128_ECB_PKCS7 Decrypt", input, original);
		}

		[Test]
		public void k128b128_CBC_None ()
		{
			byte[] key = { 0xED, 0xE4, 0xD9, 0x97, 0x8E, 0x5C, 0xF8, 0x86, 0xFE, 0x6B, 0xF4, 0xA7, 0x26, 0xDA, 0x70, 0x47 };
			byte[] iv = { 0x06, 0xE1, 0xA5, 0x97, 0x7E, 0x20, 0x0C, 0x47, 0xA4, 0xAF, 0xB8, 0xF3, 0x8D, 0x2E, 0xA9, 0xAC };
			byte[] expected = { 0xB1, 0x73, 0xDA, 0x05, 0x4C, 0x0D, 0x6C, 0x5D, 0x60, 0x72, 0x76, 0x79, 0x64, 0xA6, 0x45, 0x89, 0xA5, 0xCD, 0x35, 0x2C, 0x56, 0x12, 0x7D, 0xA6, 0x84, 0x36, 0xEB, 0xCC, 0xDF, 0x5C, 0xCB, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.None;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k128b128_CBC_None Encrypt", expected, output);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k128b128_CBC_None Decrypt", input, original);
		}

		[Test]
		public void k128b128_CBC_Zeros ()
		{
			byte[] key = { 0x7F, 0x03, 0x95, 0x4E, 0x42, 0x9E, 0x83, 0x85, 0x4B, 0x1A, 0x87, 0x36, 0xA1, 0x5B, 0xA8, 0x24 };
			byte[] iv = { 0x75, 0x49, 0x7B, 0xBE, 0x78, 0x55, 0x5F, 0xE9, 0x67, 0xCB, 0x7E, 0x30, 0x71, 0xD1, 0x36, 0x49 };
			//byte[] expected = { 0xC8, 0xE2, 0xE5, 0x14, 0x17, 0x10, 0x14, 0xA5, 0x14, 0x8E, 0x59, 0x82, 0x7C, 0x92, 0x12, 0x91, 0x49, 0xE4, 0x24, 0x2C, 0x38, 0x98, 0x91, 0x0B, 0xD8, 0x5C, 0xD0, 0x79, 0xCD, 0x35, 0x85, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.Zeros;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			// some exception can be normal... other not so!
			try {
				Encrypt (encryptor, input, output);
			}
			catch (Exception e) {
				if (e.Message != "Input buffer contains insufficient data. ")
					Assert.Fail ("k128b128_CBC_Zeros: This isn't the expected exception: " + e.ToString ());
			}
		}

		[Test]
		public void k128b128_CBC_PKCS7 ()
		{
			byte[] key = { 0x02, 0xE6, 0xC1, 0xE2, 0x7E, 0x89, 0xB9, 0x04, 0xE7, 0x9A, 0xB8, 0x83, 0xA4, 0xF8, 0x1B, 0x64 };
			byte[] iv = { 0xBC, 0xE4, 0x47, 0x1E, 0xD0, 0xDD, 0x09, 0x0D, 0xFC, 0xA1, 0x44, 0xCD, 0x88, 0x92, 0x41, 0xA5 };
			byte[] expected = { 0xEA, 0xB3, 0x9D, 0xCC, 0xE6, 0x74, 0x22, 0xE5, 0x15, 0xEE, 0x1C, 0xA9, 0x48, 0xB9, 0x55, 0x01, 0xEA, 0x9F, 0x98, 0x8D, 0x5D, 0x59, 0xB1, 0x1C, 0xEC, 0xE5, 0x68, 0xEE, 0x86, 0x22, 0x17, 0xBA, 0x95, 0x7D, 0xEC, 0x06, 0x4B, 0x48, 0x90, 0x0E, 0x75, 0x38, 0xC0, 0x28, 0x7D, 0x72, 0x32, 0xF8 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.PKCS7;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k128b128_CBC_PKCS7 Encrypt", expected, output);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k128b128_CBC_PKCS7 Decrypt", input, original);
		}


		/* Invalid parameters k128b128_CTS_None. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k128b128_CTS_Zeros. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k128b128_CTS_PKCS7. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k128b128_CFB8_None. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k128b128_CFB8_Zeros. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k128b128_CFB8_PKCS7. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k128b128_OFB8_None. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k128b128_OFB8_Zeros. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k128b128_OFB8_PKCS7. Why? Output feedback mode (OFB) is not supported by this implementation. */

		[Test]
		public void k192b128_ECB_None ()
		{
			byte[] key = { 0xA4, 0x51, 0x15, 0x32, 0xE7, 0xFC, 0x6F, 0x22, 0x73, 0x72, 0xB0, 0xAD, 0x67, 0x4C, 0x84, 0xB4, 0xB2, 0xAF, 0x50, 0x74, 0x5A, 0x4D, 0xB7, 0x2A };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0x83, 0x22, 0x1B, 0x6C, 0x66, 0x1F, 0x4A, 0xB7, 0x55, 0xAF, 0x5B, 0xBF, 0x4A, 0x05, 0x73, 0x24 };
			byte[] expected = { 0x6A, 0x1D, 0xA5, 0xBE, 0x7F, 0x6C, 0x0A, 0x98, 0x2A, 0x09, 0x4B, 0x70, 0xC1, 0xA1, 0xBC, 0x75, 0x6A, 0x1D, 0xA5, 0xBE, 0x7F, 0x6C, 0x0A, 0x98, 0x2A, 0x09, 0x4B, 0x70, 0xC1, 0xA1, 0xBC, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.None;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k192b128_ECB_None Encrypt", expected, output);

			// in ECB the first 2 blocks should be equals (as the IV is not used)
			byte[] block1 = new byte[blockLength];
			Array.Copy (output, 0, block1, 0, blockLength);
			byte[] block2 = new byte[blockLength];
			Array.Copy (output, blockLength, block2, 0, blockLength);
			AssertEquals ("k192b128_ECB_None b1==b2", block1, block2);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k192b128_ECB_None Decrypt", input, original);
		}

		[Test]
		public void k192b128_ECB_Zeros ()
		{
			byte[] key = { 0xB4, 0x65, 0x79, 0x30, 0x92, 0x6A, 0xEC, 0x78, 0xBA, 0x9B, 0x8B, 0x36, 0x7C, 0x8F, 0x6B, 0x8A, 0x79, 0x7F, 0x8A, 0xDA, 0xB4, 0x06, 0x23, 0x4C };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0x43, 0xBA, 0x1C, 0xFB, 0x33, 0xB4, 0x3B, 0x38, 0x5C, 0x21, 0x13, 0xDD, 0x9A, 0x3A, 0xF1, 0xEE };
			//byte[] expected = { 0xB1, 0x45, 0x70, 0xFC, 0xB5, 0x82, 0x49, 0x9F, 0xEA, 0x50, 0x0C, 0xEA, 0xFD, 0x13, 0xA8, 0xE8, 0xB1, 0x45, 0x70, 0xFC, 0xB5, 0x82, 0x49, 0x9F, 0xEA, 0x50, 0x0C, 0xEA, 0xFD, 0x13, 0xA8, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.Zeros;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			// some exception can be normal... other not so!
			try {
				Encrypt (encryptor, input, output);
			}
			catch (Exception e) {
				if (e.Message != "Input buffer contains insufficient data. ")
					Assert.Fail ("k192b128_ECB_Zeros: This isn't the expected exception: " + e.ToString ());
			}
		}

		[Test]
		public void k192b128_ECB_PKCS7 ()
		{
			byte[] key = { 0x06, 0xC3, 0x07, 0x6A, 0x36, 0xE5, 0xF3, 0xCF, 0x33, 0x87, 0x22, 0x03, 0x5A, 0xFA, 0x4F, 0x25, 0x9D, 0xE4, 0x81, 0xA4, 0x9E, 0xB4, 0x5D, 0x84 };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0xB0, 0xF9, 0x9F, 0x2D, 0x8D, 0xD0, 0x2D, 0xA1, 0x51, 0xDB, 0x07, 0xA3, 0x34, 0x28, 0x4F, 0x25 };
			byte[] expected = { 0xE9, 0xB9, 0xE5, 0x89, 0x0E, 0xF7, 0x3C, 0xCF, 0x63, 0x6B, 0xCD, 0x33, 0x85, 0x81, 0x02, 0x75, 0xE9, 0xB9, 0xE5, 0x89, 0x0E, 0xF7, 0x3C, 0xCF, 0x63, 0x6B, 0xCD, 0x33, 0x85, 0x81, 0x02, 0x75, 0xE8, 0x31, 0x03, 0x87, 0xFF, 0x9D, 0x7A, 0xAB, 0x81, 0x82, 0x63, 0x6B, 0xAA, 0x6F, 0x20, 0x21 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.PKCS7;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k192b128_ECB_PKCS7 Encrypt", expected, output);

			// in ECB the first 2 blocks should be equals (as the IV is not used)
			byte[] block1 = new byte[blockLength];
			Array.Copy (output, 0, block1, 0, blockLength);
			byte[] block2 = new byte[blockLength];
			Array.Copy (output, blockLength, block2, 0, blockLength);
			AssertEquals ("k192b128_ECB_PKCS7 b1==b2", block1, block2);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k192b128_ECB_PKCS7 Decrypt", input, original);
		}

		[Test]
		public void k192b128_CBC_None ()
		{
			byte[] key = { 0x8F, 0x85, 0x39, 0xC2, 0xAC, 0x25, 0xBD, 0x54, 0xDE, 0x89, 0x2A, 0x67, 0x2C, 0xF0, 0xE5, 0x7E, 0xAA, 0x7E, 0xC4, 0xFB, 0xCD, 0x31, 0xD9, 0xFA };
			byte[] iv = { 0xCA, 0xC4, 0x8D, 0x38, 0x28, 0x29, 0xC2, 0xBF, 0xD8, 0x7A, 0xCA, 0x56, 0xBF, 0x59, 0x6B, 0xCE };
			byte[] expected = { 0x22, 0x66, 0xB0, 0x6C, 0xC1, 0x18, 0xBB, 0x43, 0x6B, 0xB9, 0x42, 0x16, 0x4D, 0xFB, 0x96, 0x7C, 0xEC, 0xCA, 0xB8, 0x09, 0x02, 0x8C, 0x2E, 0x4D, 0x4D, 0x90, 0x03, 0xEA, 0x0F, 0x69, 0x20, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.None;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k192b128_CBC_None Encrypt", expected, output);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k192b128_CBC_None Decrypt", input, original);
		}

		[Test]
		public void k192b128_CBC_Zeros ()
		{
			byte[] key = { 0xA7, 0x3E, 0xEE, 0x4B, 0xF5, 0x0E, 0x05, 0x03, 0xE2, 0x50, 0xF1, 0xBC, 0xEB, 0x57, 0x60, 0x79, 0x83, 0x5D, 0xFC, 0x42, 0x65, 0x41, 0xCF, 0x48 };
			byte[] iv = { 0xC9, 0x76, 0xCE, 0x21, 0xDF, 0x46, 0xB0, 0x23, 0x19, 0xB6, 0xD5, 0x80, 0x1F, 0xBA, 0x15, 0xDB };
			//byte[] expected = { 0x63, 0xED, 0x15, 0xBE, 0xB9, 0x4E, 0x9E, 0x30, 0xB1, 0xC5, 0x31, 0xCB, 0x02, 0x88, 0xB4, 0x8F, 0xF5, 0xB0, 0x53, 0x8D, 0xD1, 0x35, 0xB7, 0x85, 0xED, 0x02, 0x79, 0x03, 0xC1, 0x13, 0xCE, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.Zeros;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			// some exception can be normal... other not so!
			try {
				Encrypt (encryptor, input, output);
			}
			catch (Exception e) {
				if (e.Message != "Input buffer contains insufficient data. ")
					Assert.Fail ("k192b128_CBC_Zeros: This isn't the expected exception: " + e.ToString ());
			}
		}

		[Test]
		public void k192b128_CBC_PKCS7 ()
		{
			byte[] key = { 0x0F, 0x00, 0x54, 0xCD, 0x2A, 0x66, 0x21, 0xF0, 0x74, 0x64, 0x65, 0xC6, 0xE1, 0xC6, 0xCD, 0x11, 0x05, 0x04, 0xA7, 0x23, 0x48, 0x4E, 0xB3, 0x84 };
			byte[] iv = { 0xDA, 0xE6, 0x7F, 0x27, 0x8A, 0xE6, 0x8E, 0x13, 0x9D, 0x15, 0x0D, 0x80, 0x4B, 0xC4, 0x9F, 0x08 };
			byte[] expected = { 0x0D, 0x7E, 0x32, 0xE0, 0xFA, 0x25, 0xB1, 0x52, 0x37, 0x27, 0xF3, 0x99, 0xA7, 0x08, 0x7F, 0x8E, 0xAA, 0x98, 0x36, 0x42, 0x21, 0xCF, 0x3B, 0xF1, 0x95, 0x99, 0xF4, 0x00, 0x36, 0x47, 0x0F, 0x25, 0x43, 0x36, 0x43, 0x68, 0x40, 0xB1, 0x1A, 0xFA, 0xDC, 0x43, 0x94, 0xD7, 0x16, 0x28, 0xFD, 0xDD };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.PKCS7;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k192b128_CBC_PKCS7 Encrypt", expected, output);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k192b128_CBC_PKCS7 Decrypt", input, original);
		}


		/* Invalid parameters k192b128_CTS_None. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k192b128_CTS_Zeros. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k192b128_CTS_PKCS7. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k192b128_CFB8_None. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k192b128_CFB8_Zeros. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k192b128_CFB8_PKCS7. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k192b128_OFB8_None. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k192b128_OFB8_Zeros. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k192b128_OFB8_PKCS7. Why? Output feedback mode (OFB) is not supported by this implementation. */

		[Test]
		public void k256b128_ECB_None ()
		{
			byte[] key = { 0x5B, 0xA0, 0xA9, 0x6B, 0x20, 0x14, 0xF4, 0x4E, 0x2E, 0x9A, 0x34, 0x84, 0xD3, 0xB9, 0x62, 0x45, 0xB1, 0x98, 0x35, 0xAE, 0xA7, 0xED, 0x80, 0x67, 0xE2, 0x77, 0xC4, 0xD5, 0x6B, 0xBD, 0x6E, 0xCF };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0xF5, 0xBD, 0x6D, 0xDF, 0x0C, 0x8E, 0xC5, 0x39, 0x25, 0xBE, 0x1A, 0x80, 0xF8, 0x79, 0xEC, 0x93 };
			byte[] expected = { 0x54, 0xF5, 0x87, 0xE7, 0x73, 0xB7, 0x04, 0xBF, 0xBB, 0x16, 0x3D, 0x5A, 0xC0, 0x68, 0x7C, 0x17, 0x54, 0xF5, 0x87, 0xE7, 0x73, 0xB7, 0x04, 0xBF, 0xBB, 0x16, 0x3D, 0x5A, 0xC0, 0x68, 0x7C, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.None;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k256b128_ECB_None Encrypt", expected, output);

			// in ECB the first 2 blocks should be equals (as the IV is not used)
			byte[] block1 = new byte[blockLength];
			Array.Copy (output, 0, block1, 0, blockLength);
			byte[] block2 = new byte[blockLength];
			Array.Copy (output, blockLength, block2, 0, blockLength);
			AssertEquals ("k256b128_ECB_None b1==b2", block1, block2);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k256b128_ECB_None Decrypt", input, original);
		}

		[Test]
		public void k256b128_ECB_Zeros ()
		{
			byte[] key = { 0x77, 0xE1, 0xB2, 0xF9, 0x14, 0xF0, 0x77, 0xCE, 0xDB, 0x28, 0xD4, 0xA5, 0x0E, 0xA6, 0x73, 0x23, 0xD8, 0x46, 0xB7, 0x1A, 0x16, 0x92, 0xDB, 0x7E, 0x80, 0xDF, 0x5E, 0x9A, 0x16, 0x08, 0xFF, 0x6D };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0x48, 0xEC, 0x4A, 0x12, 0xAC, 0x9C, 0xB5, 0x72, 0xEB, 0x12, 0x14, 0xFB, 0xE1, 0x6D, 0xCF, 0xA3 };
			//byte[] expected = { 0x82, 0x6C, 0xC7, 0xA6, 0xC2, 0x57, 0x07, 0xF9, 0x2F, 0x92, 0x95, 0x90, 0x65, 0xFA, 0x1D, 0xFA, 0x82, 0x6C, 0xC7, 0xA6, 0xC2, 0x57, 0x07, 0xF9, 0x2F, 0x92, 0x95, 0x90, 0x65, 0xFA, 0x1D, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.Zeros;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			// some exception can be normal... other not so!
			try {
				Encrypt (encryptor, input, output);
			}
			catch (Exception e) {
				if (e.Message != "Input buffer contains insufficient data. ")
					Assert.Fail ("k256b128_ECB_Zeros: This isn't the expected exception: " + e.ToString ());
			}
		}

		[Test]
		public void k256b128_ECB_PKCS7 ()
		{
			byte[] key = { 0x19, 0xC2, 0x2D, 0x12, 0x57, 0x2B, 0xEF, 0x0C, 0xA2, 0xC7, 0x26, 0x7E, 0x35, 0xAD, 0xC5, 0x12, 0x53, 0x5D, 0xEE, 0xD7, 0x69, 0xC3, 0xB4, 0x0D, 0x9B, 0xEF, 0x36, 0xF7, 0xB2, 0xF2, 0xB0, 0x37 };
			// not used for ECB but make the code more uniform
			byte[] iv = { 0xCF, 0x8D, 0xBE, 0xE0, 0x41, 0xC6, 0xB9, 0xB5, 0x2D, 0x8A, 0x59, 0x92, 0x82, 0xF4, 0xE8, 0x74 };
			byte[] expected = { 0xAD, 0x99, 0x9A, 0xE2, 0x5B, 0xE7, 0xFB, 0x74, 0xE8, 0xAB, 0xEE, 0x5D, 0xCA, 0x0F, 0x0A, 0x7A, 0xAD, 0x99, 0x9A, 0xE2, 0x5B, 0xE7, 0xFB, 0x74, 0xE8, 0xAB, 0xEE, 0x5D, 0xCA, 0x0F, 0x0A, 0x7A, 0x8F, 0xAD, 0xBB, 0xC2, 0x18, 0xB8, 0xF0, 0xFF, 0x59, 0x7D, 0xF8, 0xF1, 0x6A, 0x21, 0x9C, 0xF3 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.ECB;
			algo.Padding = PaddingMode.PKCS7;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k256b128_ECB_PKCS7 Encrypt", expected, output);

			// in ECB the first 2 blocks should be equals (as the IV is not used)
			byte[] block1 = new byte[blockLength];
			Array.Copy (output, 0, block1, 0, blockLength);
			byte[] block2 = new byte[blockLength];
			Array.Copy (output, blockLength, block2, 0, blockLength);
			AssertEquals ("k256b128_ECB_PKCS7 b1==b2", block1, block2);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k256b128_ECB_PKCS7 Decrypt", input, original);
		}

		[Test]
		public void k256b128_CBC_None ()
		{
			byte[] key = { 0xE8, 0x74, 0x24, 0x77, 0x2B, 0xBE, 0x6C, 0x99, 0x2E, 0xFC, 0xB5, 0x85, 0xC9, 0xA1, 0xD7, 0x9C, 0x24, 0xF1, 0x86, 0x0B, 0xEA, 0xAB, 0xCB, 0x06, 0x47, 0x2E, 0x26, 0x6C, 0xAF, 0x24, 0x87, 0xA7 };
			byte[] iv = { 0x15, 0x7E, 0xA5, 0xE5, 0x47, 0xFA, 0x40, 0x30, 0x0A, 0xAA, 0x9E, 0x68, 0x8E, 0x4D, 0x2D, 0xA4 };
			byte[] expected = { 0xEF, 0x05, 0x1C, 0x5C, 0xEA, 0xED, 0x34, 0x28, 0x9E, 0x21, 0x9C, 0x2C, 0x96, 0xF5, 0xF7, 0xDA, 0x55, 0xD4, 0x88, 0x0A, 0x73, 0xF1, 0x8D, 0xBC, 0x8F, 0x17, 0x26, 0x86, 0x8A, 0xC1, 0x4B, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.None;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k256b128_CBC_None Encrypt", expected, output);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k256b128_CBC_None Decrypt", input, original);
		}

		[Test]
		public void k256b128_CBC_Zeros ()
		{
			byte[] key = { 0x50, 0x54, 0x8C, 0x92, 0xE5, 0xFD, 0x08, 0x03, 0xEA, 0x15, 0xBB, 0xB9, 0x39, 0x8B, 0x6E, 0xF0, 0xF5, 0x64, 0x49, 0x0E, 0x0F, 0x8F, 0x41, 0xF9, 0xA6, 0x1E, 0xD4, 0xD2, 0xB6, 0xF2, 0xB6, 0x4B };
			byte[] iv = { 0x32, 0x9B, 0x60, 0xF7, 0xBE, 0x0F, 0x5F, 0xA5, 0xD2, 0x7A, 0x1F, 0xB4, 0x01, 0x76, 0xD1, 0xCD };
			//byte[] expected = { 0x6C, 0x55, 0xAD, 0x57, 0xEE, 0x78, 0x1D, 0x69, 0x82, 0x8D, 0xE5, 0x52, 0x4C, 0x76, 0xD7, 0xF1, 0xFA, 0xFC, 0xD1, 0x2D, 0xDC, 0x0F, 0xE4, 0x4F, 0xF0, 0xE5, 0xB0, 0x2B, 0x28, 0xBF, 0x07, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.Zeros;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			// some exception can be normal... other not so!
			try {
				Encrypt (encryptor, input, output);
			}
			catch (Exception e) {
				if (e.Message != "Input buffer contains insufficient data. ")
					Assert.Fail ("k256b128_CBC_Zeros: This isn't the expected exception: " + e.ToString ());
			}
		}

		[Test]
		public void k256b128_CBC_PKCS7 ()
		{
			byte[] key = { 0x8B, 0x8B, 0x4C, 0x04, 0x8C, 0x16, 0x16, 0x91, 0xBE, 0x79, 0x35, 0xF6, 0x26, 0x01, 0xF8, 0x06, 0x8F, 0xC7, 0x6D, 0xD6, 0xFE, 0xDE, 0xCF, 0xD8, 0xDC, 0xE1, 0x97, 0x9D, 0xA9, 0xD0, 0x96, 0x86 };
			byte[] iv = { 0xA0, 0xF5, 0x25, 0xE5, 0x17, 0xEA, 0x37, 0x18, 0x17, 0x56, 0x26, 0x1C, 0x63, 0x95, 0xC3, 0xAD };
			byte[] expected = { 0x42, 0x33, 0x8E, 0xDE, 0x2E, 0xDA, 0xC9, 0xC6, 0x97, 0xA2, 0xAE, 0xE1, 0x15, 0x00, 0xDE, 0x4A, 0x39, 0x0B, 0xEB, 0xC8, 0xF9, 0x9F, 0x00, 0x05, 0xCF, 0xB5, 0x32, 0x46, 0x91, 0xFC, 0x28, 0x23, 0xF4, 0xC5, 0xCE, 0x42, 0x63, 0x3F, 0x82, 0x7D, 0x2A, 0xC4, 0xB5, 0x09, 0x67, 0xC7, 0x33, 0x3F };

			SymmetricAlgorithm algo = Create ();
			algo.Mode = CipherMode.CBC;
			algo.Padding = PaddingMode.PKCS7;
			algo.BlockSize = 128;
			int blockLength = (algo.BlockSize >> 3);
			byte[] input = new byte [blockLength * 2 + (blockLength >> 1)];
			byte[] output = new byte [blockLength * 3];
			ICryptoTransform encryptor = algo.CreateEncryptor(key, iv);
			Encrypt (encryptor, input, output);
			AssertEquals ("k256b128_CBC_PKCS7 Encrypt", expected, output);
			byte[] reverse = new byte [blockLength * 3];
			ICryptoTransform decryptor = algo.CreateDecryptor(key, iv);
			Decrypt (decryptor, output, reverse);
			byte[] original = new byte [input.Length];
			Array.Copy (reverse, 0, original, 0, original.Length);
			AssertEquals ("k256b128_CBC_PKCS7 Decrypt", input, original);
		}


		/* Invalid parameters k256b128_CTS_None. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k256b128_CTS_Zeros. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k256b128_CTS_PKCS7. Why? Specified cipher mode is not valid for this algorithm. */

		/* Invalid parameters k256b128_CFB8_None. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k256b128_CFB8_Zeros. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k256b128_CFB8_PKCS7. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k256b128_OFB8_None. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k256b128_OFB8_Zeros. Why? Output feedback mode (OFB) is not supported by this implementation. */

		/* Invalid parameters k256b128_OFB8_PKCS7. Why? Output feedback mode (OFB) is not supported by this implementation. */
	}
}
