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

class Program {

	static void GenerateHash (string name)
	{
		string template = @"// NOTE: Generated code DO NOT EDIT
//
// Author: 
//	Sebastien Pouliot  <sebastien@gmail.com>
// 
// Copyright 2012 Symform Inc.
// 
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Security.Cryptography;
using Crimson.CryptoDev;

namespace Crimson.Security.Cryptography {

	public class {0}Kernel : {0} {

		HashHelper helper;


		public {0}Kernel ()
		{
		}

		~{0}Kernel ()
		{
			Dispose (false);
		}

		protected override void Dispose (bool disposing)
		{
			if (disposing && (helper != null)) {
				helper.Dispose ();
				helper = null;
				GC.SuppressFinalize (this);
			}
			base.Dispose (disposing);
		}

		public override void Initialize ()
		{
			helper = new HashHelper (Cipher.{0});
		}

		protected override void HashCore (byte[] data, int start, int length) 
		{
			if (helper == null)
				Initialize ();
			helper.Update (data, start, length);
		}

		protected override byte[] HashFinal () 
		{
			if (helper == null)
				Initialize ();
			return helper.Final (HashSize >> 3);
		}
	}
}";
		string filename = Path.Combine (OutputDirectory,
			String.Format ("{0}Kernel.g.cs", name));
		string content = template.Replace ("{0}", name);
		File.WriteAllText (filename, content);
	}

	static void GenerateSymmetricAlgorithm (string name, string fallback, string ecb, string cbc)
	{
		string template = @"// NOTE: Generated code DO NOT EDIT
//
// Author: Sebastien Pouliot  <sebastien@gmail.com>
// See LICENSE for copyrights and restrictions
//
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

using Mono.Security.Cryptography;
using Crimson.CryptoDev;

namespace Crimson.Security.Cryptography {

	public class {0}Kernel : {0} {
		
		const int BufferBlockSize = Int32.MaxValue;

		public {0}Kernel ()
		{
		}
		
		public override void GenerateIV ()
		{
			IVValue = KeyBuilder.IV (BlockSizeValue >> 3);
		}
		
		public override void GenerateKey ()
		{
			KeyValue = KeyBuilder.Key (KeySizeValue >> 3);
		}
	
		{1} Fallback ()
		{
			{1} r = new {1} ();
			r.Mode = Mode;
			r.Padding = Padding;
			return r;
		}
	
		public override ICryptoTransform CreateDecryptor (byte[] rgbKey, byte[] rgbIV) 
		{
			try {
				switch (Mode) {
				case CipherMode.CBC:
					return new CryptoDevTransform (this, Cipher.{3}, false, rgbKey, rgbIV, BufferBlockSize);
				case CipherMode.ECB:
					return new CryptoDevTransform (this, Cipher.{2}, false, rgbKey, rgbIV, BufferBlockSize);
				}
			}
			catch (CryptographicException) {
				// the kernel might not have the required mode (even for 'generic') available
			}
			// other modes, effectivelty CFB, will be implemented on top
			// on ECB, one block at the time
			return Fallback ().CreateDecryptor (rgbKey, rgbIV);
		}
		
		public override ICryptoTransform CreateEncryptor (byte[] rgbKey, byte[] rgbIV) 
		{
			try {
				switch (Mode) {
				case CipherMode.CBC:
					return new CryptoDevTransform (this, Cipher.{3}, true, rgbKey, rgbIV, BufferBlockSize);
				case CipherMode.ECB:
					return new CryptoDevTransform (this, Cipher.{2}, true, rgbKey, rgbIV, BufferBlockSize);
				}
			}
			catch (CryptographicException) {
				// the kernel might not have the required mode (even for 'generic') available
			}
			// other modes, effectivelty CFB, will be implemented on top
			// on ECB, one block at the time
			return Fallback ().CreateEncryptor (rgbKey, rgbIV);
		}
	}
}";
		string filename = Path.Combine (OutputDirectory,
			String.Format ("{0}Kernel.g.cs", name));
		string content = template.Replace ("{0}", name).
			Replace ("{1}", fallback).
			Replace ("{2}", ecb).
			Replace ("{3}", cbc);
		File.WriteAllText (filename, content);
	}

	static string OutputDirectory { get; set; }

	static void Main (string[] args)
	{
		OutputDirectory = args.Length == 0 ? "." : args [0];

		GenerateHash ("SHA1");		// CRYPTO_SHA1
		GenerateHash ("SHA256");	// CRYPTO_SHA256
#if UNTESTED
		GenerateHash ("MD5");		// CRYPTO_MD5
		GenerateHash ("RIPEMD160");	// CRYPTO_RIPEMD160
		GenerateHash ("SHA384");	// CRYPTO_SHA2_384
		GenerateHash ("SHA512");	// CRYPTO_SHA2_512
#endif
		GenerateSymmetricAlgorithm ("Aes", "RijndaelManaged", "AES_ECB", "AES_CBC");
#if UNTESTED
		GenerateSymmetricAlgorithm ("Des", "DESCryptoServiceProvider", null, "DES_CBC");
		GenerateSymmetricAlgorithm ("TripleDes", "TripleDESCryptoServiceProvider", null, "3DES_CBC");
		// BLF (Blowfish), CAST, SKIPJACK and Camellia are not part of the .NET framework 
		// and would require a additional base classes and fallbacks
#endif
	}
}
