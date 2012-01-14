using System;
using System.Security.Cryptography;
using System.Text;

class Program {

	static void Test (SymmetricAlgorithm cipher)
	{
		if (cipher is Rijndael || cipher is Aes) {
			Console.WriteLine ("Testing results wrt FIPS 197 test vectors");
			FIPS197_AppendixB (cipher);
			FIPS197_AppendixC1 (cipher);
			FIPS197_AppendixC2 (cipher);
			FIPS197_AppendixC3 (cipher);
		} else {
			Console.WriteLine ("No test vectors were found.");
			return;
		}
	}

	static void FIPS197_AppendixB (SymmetricAlgorithm cipher) 
	{
		byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
		byte[] iv = new byte[16]; // empty - not used for ECB
		byte[] input = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
		byte[] expected = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
		Console.WriteLine ("FIPS 197 B:  {0}",
			Test (cipher, key, iv, input, expected) ? "PASS" : "FAIL");
	}

	// FIPS197 C.1 AES-128 (Nk=4, Nr=10)
	static void FIPS197_AppendixC1 (SymmetricAlgorithm cipher) 
	{
		byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
		byte[] iv = new byte[16]; // empty - not used for ECB
		byte[] input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		byte[] expected = { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
		Console.WriteLine ("FIPS 197 C1: {0}",
			Test (cipher, key, iv, input, expected) ? "PASS" : "FAIL");
	}

	// FIPS197 C.2 AES-192 (Nk=6, Nr=12)
	static void FIPS197_AppendixC2 (SymmetricAlgorithm cipher) 
	{
		byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
		byte[] iv = new byte[16]; // empty - not used for ECB
		byte[] input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		byte[] expected = { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
		Console.WriteLine ("FIPS 197 C2: {0}",
			Test (cipher, key, iv, input, expected) ? "PASS" : "FAIL");
	}

	// C.3 AES-256 (Nk=8, Nr=14)
	static void FIPS197_AppendixC3 (SymmetricAlgorithm cipher) 
	{
		byte[] key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
		byte[] iv = new byte[16]; // empty - not used for ECB
		byte[] input = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
		byte[] expected = { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
		Console.WriteLine ("FIPS 197 C3: {0}",
			Test (cipher, key, iv, input, expected) ? "PASS" : "FAIL");
	}

	static bool Test (SymmetricAlgorithm cipher, byte[] key, byte[] iv, byte[] input, byte[] expected)
	{
		cipher.Mode = CipherMode.ECB;
		cipher.KeySize = key.Length * 8;
		cipher.Padding = PaddingMode.Zeros;

		byte[] output = new byte [input.Length];
		ICryptoTransform encryptor = cipher.CreateEncryptor (key, iv);
		encryptor.TransformBlock (input, 0, input.Length, output, 0);
		if (!Compare (output, expected))
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


	static void Perf (SymmetricAlgorithm cipher)
	{
		Console.WriteLine ("Performance tests for different block sizes, 30 seconds each");
		int block = cipher.BlockSize;
		while (block <= 64 * 1024 + 1) {
			Speed (cipher, block);
			block <<= 2;
		}
	}
	
	static void Speed (SymmetricAlgorithm cipher, int block)
	{
		byte[] input = new byte [block];
		byte[] output = new byte [block];
		DateTime now = DateTime.UtcNow;
		long size = 0;
		ICryptoTransform transform = cipher.CreateEncryptor ();
		while ((DateTime.UtcNow - now).TotalSeconds < 30) {
			transform.TransformBlock (input, 0, input.Length, output, 0);
			size += input.Length;
		}
		transform.TransformFinalBlock (input, 0, input.Length);
		size += input.Length;
		double speed = size / (DateTime.UtcNow - now).TotalSeconds;
		Console.WriteLine ("{0}: {1}: {2} Mbytes/sec", block, cipher, speed / 1024 / 1024);
	}

	static void Main (string[] args)
	{
		foreach (string arg in args) {
			SymmetricAlgorithm cipher = (SymmetricAlgorithm) CryptoConfig.CreateFromName (arg);
			Console.WriteLine ("{0}: {1}", arg, cipher);
			Test (cipher);
			Perf (cipher);
		}
	}
}
