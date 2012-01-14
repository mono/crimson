//
// SHA1Test.cs - NUnit Test Cases for SHA1
//
// Author:
//	Sebastien Pouliot  <sebastien@xamarin.com>
//
// (C) 2002 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004, 2007 Novell, Inc (http://www.novell.com)
// Copyright 2012 Xamarin Inc. (http://www.xamarin.com)
//

using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crimson.Test.Base {

// References:
// a.	FIPS PUB 180-1: Secure Hash Standard
//	http://csrc.nist.gov/publications/fips/fips180-1/fip180-1.txt

	public class SHA1Test : HashAlgorithmTest {
	
		// test vectors from NIST FIPS 186-2
	
		private string input1 = "abc";
		private string input2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	
		public void FIPS186_Test1 (SHA1 hash) 
		{
			string className = hash.ToString ();
			byte[] result = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
			byte[] input = Encoding.Default.GetBytes (input1);
			
			string testName = className + " 1";
			FIPS186_a (testName, hash, input, result);
			FIPS186_b (testName, hash, input, result);
			FIPS186_c (testName, hash, input, result);
			FIPS186_d (testName, hash, input, result);
			FIPS186_e (testName, hash, input, result);
		}
	
		public void FIPS186_Test2 (SHA1 hash) 
		{
			string className = hash.ToString ();
			byte[] result = { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };
			byte[] input = Encoding.Default.GetBytes (input2);
			
			string testName = className + " 2";
			FIPS186_a (testName, hash, input, result);
			FIPS186_b (testName, hash, input, result);
			FIPS186_c (testName, hash, input, result);
			FIPS186_d (testName, hash, input, result);
			FIPS186_e (testName, hash, input, result);
		}
	
		public void FIPS186_Test3 (SHA1 hash) 
		{
			string className = hash.ToString ();
			byte[] result = { 0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f };
			byte[] input = new byte [1000000];
			for (int i = 0; i < 1000000; i++)
				input[i] = 0x61; // a
			
			string testName = className + " 3";
			FIPS186_a (testName, hash, input, result);
			FIPS186_b (testName, hash, input, result);
			FIPS186_c (testName, hash, input, result);
			FIPS186_d (testName, hash, input, result);
			FIPS186_e (testName, hash, input, result);
		}
	
		public void FIPS186_a (string testName, SHA1 hash, byte[] input, byte[] result) 
		{
			byte[] output = hash.ComputeHash (input); 
			Assert.AreEqual (result, output, testName + ".a.1");
			Assert.AreEqual (result, hash.Hash, testName + ".a.2");
			// required or next operation will still return old hash
			hash.Initialize ();
		}
	
		public void FIPS186_b (string testName, SHA1 hash, byte[] input, byte[] result) 
		{
			byte[] output = hash.ComputeHash (input, 0, input.Length); 
			Assert.AreEqual (result, output, testName + ".b.1");
			Assert.AreEqual (result, hash.Hash, testName + ".b.2");
			// required or next operation will still return old hash
			hash.Initialize ();
		}
	
		public void FIPS186_c (string testName, SHA1 hash, byte[] input, byte[] result) 
		{
			MemoryStream ms = new MemoryStream (input);
			byte[] output = hash.ComputeHash (ms); 
			Assert.AreEqual (result, output, testName + ".c.1");
			Assert.AreEqual (result, hash.Hash, testName + ".c.2");
			// required or next operation will still return old hash
			hash.Initialize ();
		}
	
		public void FIPS186_d (string testName, SHA1 hash, byte[] input, byte[] result) 
		{
			hash.TransformFinalBlock (input, 0, input.Length);
			// LAMESPEC or FIXME: TransformFinalBlock doesn't return HashValue !
			// AssertEquals( testName + ".d.1", result, output );
			Assert.AreEqual (result, hash.Hash, testName + ".d");
			// required or next operation will still return old hash
			hash.Initialize ();
		}
	
		public void FIPS186_e (string testName, SHA1 hash, byte[] input, byte[] result) 
		{
			byte[] copy = new byte [input.Length];
			for (int i=0; i < input.Length - 1; i++)
				hash.TransformBlock (input, i, 1, copy, i);
			hash.TransformFinalBlock (input, input.Length - 1, 1);
			// LAMESPEC or FIXME: TransformFinalBlock doesn't return HashValue !
			// AssertEquals (testName + ".e.1", result, output);
			Assert.AreEqual (result, hash.Hash, testName + ".e");
			// required or next operation will still return old hash
			hash.Initialize ();
		}
		
		// none of those values changes for any implementation of SHA1
		[Test]
		public virtual void StaticInfo () 
		{
			string className = hash.ToString ();
			Assert.AreEqual (160, hash.HashSize, className + ".HashSize");
			Assert.AreEqual (1, hash.InputBlockSize, className + ".InputBlockSize");
			Assert.AreEqual (1, hash.OutputBlockSize, className + ".OutputBlockSize");
		}
	}
}
