using System;
using System.IO;
using System.Security.Cryptography;
//using Mono.Security.Cryptography;

class Program {

	// we avoid using CryptoConfig (via SHA1.Create) to get "true" results
	static HashAlgorithm CreateFromName (string name)
	{
		switch (name) {
		case "MD5":
			return new MD5CryptoServiceProvider ();
		case "SHA1":
			return new SHA1CryptoServiceProvider ();
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
