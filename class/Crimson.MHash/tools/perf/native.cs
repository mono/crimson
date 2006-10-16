using System;
using System.IO;
using System.Security.Cryptography;
using Crimson.Security.Cryptography;

class Program {

	// we avoid using CryptoConfig (via SHA1.Create) to get "true" results
	static HashAlgorithm CreateFromName (string name)
	{
		switch (name.ToUpper ()) {

		case "ADLER32":
			return new ADLER32Native ();
		case "CRC32B":
			return new CRC32BNative ();
		case "CRC32":
			return new CRC32Native ();
		case "GOST":
			return new GOSTNative ();
		case "HAVAL128":
			return new HAVAL128Native ();
		case "HAVAL160":
			return new HAVAL160Native ();
		case "HAVAL192":
			return new HAVAL192Native ();
		case "HAVAL224":
			return new HAVAL224Native ();
		case "HAVAL256":
			return new HAVAL256Native ();
		case "MD2":
			return new MD2Native ();
		case "MD4":
			return new MD4Native ();
		case "MD5":
			return new MD5Native ();
		case "RIPEMD128":
			return new RIPEMD128Native ();
		case "RIPEMD160":
			return new RIPEMD160Native ();
		case "RIPEMD256":
			return new RIPEMD256Native ();
		case "RIPEMD320":
			return new RIPEMD320Native ();
		case "SHA1":
			return new SHA1Native ();
		case "SHA224":
			return new SHA224Native ();
		case "SHA256":
			return new SHA256Native ();
		case "SHA384":
			return new SHA384Native ();
		case "SHA512":
			return new SHA512Native ();
		case "SNEFRU128":
			return new SNEFRU128Native ();
		case "SNEFRU256.cs":
			return new SNEFRU256Native ();
		case "TIGER128":
			return new TIGER128Native ();
		case "TIGER160":
			return new TIGER160Native ();
		case "TIGER192":
			return new TIGER192Native ();
		case "WHIRLPOOL":
			return new WHIRLPOOLNative ();

		default:
			throw new NotSupportedException (String.Format ("Unknown hash algorithm '{0}'.", name));
		}
	}

	static void Main (string[] args)
	{
		using (HashAlgorithm digest = CreateFromName (args [0])) {
			using (FileStream fs = File.OpenRead (args[1])){
				Console.WriteLine (BitConverter.ToString (digest.ComputeHash (fs)));
			}
		}
	}
}
