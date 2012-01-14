using System;
using System.Security.Cryptography;
using System.Text;

class Program {

	static void Test (HashAlgorithm digest)
	{
		byte[] result1, result2, result3;

		if (digest is SHA1) {
			Console.WriteLine ("Testing results wrt FIPS 180-1 test vectors");
			result1 = new byte [] { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 
				0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
			result2 = new byte [] { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 
				0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };
			result3 = new byte [] { 0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 
				0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f };
		} else if (digest is SHA256) {
			Console.WriteLine ("Testing results wrt FIPS 180-2 test vectors");
			result1 = new byte [] { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 
				0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 
				0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 
				0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
			result2 = new byte [] { 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 
				0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 
				0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 
				0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1 };
			result3 = new byte [] { 0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 
				0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67, 
				0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 
				0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0 };
		} else {
			Console.WriteLine ("No test vectors were found.");
			return;
		}
		string input1 = "abc";
		string input2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

		byte[] input = Encoding.Default.GetBytes (input1);
		byte[] output = digest.ComputeHash (input);
		Console.WriteLine ("FIPS 180 Test 1: {0}",
			BitConverter.ToString (result1) != BitConverter.ToString (output) ?
			"FAIL" : "PASS");

		input = Encoding.Default.GetBytes (input2);
		output = digest.ComputeHash (input);
		Console.WriteLine ("FIPS 180 Test 2: {0}",
			BitConverter.ToString (result2) != BitConverter.ToString (output) ?
			"FAIL" : "PASS");
	
		input = new byte [1000000];
		for (int i = 0; i < 1000000; i++)
			input[i] = 0x61; // a
		output = digest.ComputeHash (input);
		Console.WriteLine ("FIPS 180 Test 3: {0}",
			BitConverter.ToString (result3) != BitConverter.ToString (output) ?
			"FAIL" : "PASS");
	}

	static void Perf (HashAlgorithm digest)
	{
		Console.WriteLine ("Performance tests for different block sizes, 30 seconds each");
		int block = 1;
		while (block <= 64 * 1024) {
			Speed (digest, block);
			block <<= 2;
		}
	}
	
	static void Speed (HashAlgorithm digest, int block)
	{
		byte[] input = new byte [block];
		byte[] output = new byte [block];
		DateTime now = DateTime.UtcNow;
		long size = 0;
		while ((DateTime.UtcNow - now).TotalSeconds < 30) {
			digest.TransformBlock (input, 0, input.Length, output, 0);
			size += input.Length;
		}
		digest.TransformFinalBlock (input, 0, input.Length);
		size += input.Length;
		double speed = size / (DateTime.UtcNow - now).TotalSeconds;
		Console.WriteLine ("{0}: {1}: {2} Mbytes/sec", block, digest, speed / 1024 / 1024);
	}

	static void Main (string[] args)
	{
		foreach (string arg in args) {
			HashAlgorithm hash = (HashAlgorithm) CryptoConfig.CreateFromName (arg);
			Console.WriteLine ("{0}: {1}", arg, hash);
			Test (hash);
			Perf (hash);
		}
	}
}
