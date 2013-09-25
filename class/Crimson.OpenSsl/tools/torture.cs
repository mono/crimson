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
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Crimson.Security.Cryptography;

class Program {

	static bool verbose;

	static byte[] sha_a_input = Encoding.Default.GetBytes ("abc");
	static byte[] sha_b_input = Encoding.Default.GetBytes ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
	static byte[] sha_c_input;

	static Program ()
	{
		sha_c_input = new byte [1000000];
		for (int i = 0; i < 1000000; i++)
			sha_c_input[i] = 0x61; // a
	}

	static void Main (string [] args)
	{
		verbose = args.Length > 0;

		Parallel.Invoke (
			() => { SHA1a ();	},
			() => { SHA1b ();	},
			() => { SHA1c ();	},
			() => { SHA256a ();	},
			() => { SHA256b ();	},
			() => { SHA256c ();	},
			() => { AESa ();	},
			() => { AESb ();	},
			() => { AESc ();	},
			() => { AESd ();	}
		);
		Console.WriteLine ("End");
        }

	static void SHA1 (string name, int max, byte[] input, byte[] output)
	{
		int i = 0;
		try {
			for (; i < max; i++) {
				using (SHA1 digest = new SHA1Kernel ()) {
					if (!Compare (output, digest.ComputeHash (input)))
						throw new Exception (name + " " + i.ToString ());
				}
				Process (name, i, max);
			}
		}
		catch (Exception e) {
			Console.WriteLine ("{0} #{1} : {2}", name, i, e);
		}
	}

	static byte[] sha1_a_output = new byte [] {
		0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 
		0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };

	static void SHA1a ()
	{
		SHA1 ("SHA1a", 10000, sha_a_input, sha1_a_output);
	}

	static byte[] sha1_b_output = new byte [] {
		0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 
		0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };

	static void SHA1b ()
	{
		SHA1 ("SHA1b", 5000, sha_b_input, sha1_b_output);
	}

	static byte[] sha1_c_output = new byte [] {
		0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 
		0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f };

	static void SHA1c ()
	{
		SHA1 ("SHA1c", 2000, sha_c_input, sha1_c_output);
	}

	static void SHA256 (string name, int max, byte[] input, byte[] output)
	{
		int i = 0;
		try {
			for (; i < max; i++) {
				using (SHA256 digest = new SHA256Kernel ()) {
					if (!Compare (output, digest.ComputeHash (input)))
						throw new Exception (name + " " + i.ToString ());
				}
				Process (name, i, max);
			}
		}
		catch (Exception e) {
			Console.WriteLine ("{0} #{1} : {2}", name, i, e);
		}
	}

	static byte[] sha256_a_output = new byte [] {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };

	static void SHA256a ()
	{
		SHA256 ("SHA256a", 8000, sha_a_input, sha256_a_output);
	}

	static byte[] sha256_b_output = new byte [] {
		0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 
		0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };

	static void SHA256b ()
	{
		SHA256 ("SHA256b", 4000, sha_b_input, sha256_b_output);
	}

	static byte[] sha256_c_output = new byte [] {
		0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 
		0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67, 
		0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 
		0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 };

	static void SHA256c ()
	{
		SHA256 ("SHA256c", 2000, sha_c_input, sha256_c_output);
	}

	static void Process (string name, int iteration, int max)
	{
		if (!verbose)
			return;
		if (iteration % 1000 == 0)
			Console.WriteLine ("{0} {1}/{2} ({3})", name, iteration, max, Thread.CurrentThread.ManagedThreadId);
	}

	static byte[] aes_iv = new byte [16];

	static void AES (string name, int max, byte[] key, byte[] input, byte[] expected) 
	{
		int i = 0;
		try {
			for (; i < max; i++) {
				using (Aes cipher = new AesKernel ()) {
					cipher.Mode = CipherMode.ECB;
					cipher.KeySize = key.Length * 8;
					cipher.Padding = PaddingMode.Zeros;

					byte[] output = new byte [input.Length];
					ICryptoTransform encryptor = cipher.CreateEncryptor (key, aes_iv);
					encryptor.TransformBlock (input, 0, input.Length, output, 0);
					if (!Compare (output, expected))
						throw new Exception ("encryptor");
	
					byte[] original = new byte [output.Length];
					ICryptoTransform decryptor = cipher.CreateDecryptor (key, aes_iv); 
					decryptor.TransformBlock (output, 0, output.Length, original, 0);
					if (!Compare (original, input))
						throw new Exception ("decryptor");
				}
				Process (name, i, max);
			}
		}
		catch (Exception e) {
			Console.WriteLine ("{0} #{1} : {2}", name, i, e);
		}
	}


	static byte[] aes_a_key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	static byte[] aes_a_input = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	static byte[] aes_a_expected = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

	static void AESa () 
	{
		AES ("AESa", 4000, aes_a_key, aes_a_input, aes_a_expected);
	}

	static byte[] aes_b_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	static byte[] aes_b_input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	static byte[] aes_b_expected = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };

	static void AESb () 
	{
		AES ("AESb", 4000, aes_b_key, aes_b_input, aes_b_expected);
	}

	static byte[] aes_c_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	static byte[] aes_c_input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	static byte[] aes_c_expected = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };

	static void AESc () 
	{
		AES ("AESc", 3000, aes_c_key, aes_c_input, aes_c_expected);
	}

	static byte[] aes_d_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	static byte[] aes_d_input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	static byte[] aes_d_expected = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

	static void AESd () 
	{
		AES ("AESc", 2000, aes_d_key, aes_d_input, aes_d_expected);
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
}
