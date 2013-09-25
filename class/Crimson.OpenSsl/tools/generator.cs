//
// Author: 
//	Sebastien Pouliot  <sebastien@gmail.com>
// 
// Copyright 2013 Symform Inc.
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
//	Bassam Tabbara  <bassam@symform.com>
// 
// Copyright 2013 Symform Inc.
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

using System.Security.Cryptography;
using Crimson.OpenSsl;

namespace Crimson.Security.Cryptography {

	public class {0}OpenSsl : {0} {

        private HashHelper helper;

        protected override void Dispose(bool disposing)
        {
            if (disposing && helper != null)
            {
                helper.Dispose();
                helper = null;
            }
            base.Dispose(disposing);
        }

        public override void Initialize()
        {
            helper = new HashHelper(Native.EVP_{1}(), this.HashSize);
        }

        protected override void HashCore(byte[] data, int start, int length)
        {
            if (this.helper == null)
            {
                this.Initialize();
            }

            helper.Update(data, start, length);
        }

        protected override byte[] HashFinal()
        {
            if (this.helper == null)
            {
                this.Initialize();
            }

            return helper.Final();
        }
	}
}";
		string filename = Path.Combine (OutputDirectory,
			String.Format ("{0}OpenSsl.g.cs", name));
		string content = template.Replace ("{0}", name).
			Replace ("{1}", name.ToLowerInvariant ());
		File.WriteAllText (filename, content);
	}

	static void GenerateSymmetricAlgorithm (string name, string fallback, string ecb, string cbc)
	{
		string template = @"// NOTE: Generated code DO NOT EDIT
//
// Author: Bassam Tabbara  <bassam@symform.com>
// See LICENSE for copyrights and restrictions
//
using System.Security.Cryptography;
using Crimson.OpenSsl;

namespace Crimson.Security.Cryptography {

	public class {0}OpenSsl : {0} {
		
        public static RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        public override void GenerateIV()
        {
            IVValue = new byte[BlockSizeValue >> 3];
            Rng.GetBytes(IVValue);
        }

        public override void GenerateKey()
        {
            KeyValue = new byte[KeySizeValue >> 3];
            Rng.GetBytes(KeyValue);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            try
            {
                if (BlockSize == 128)
                {
                    return new OpenSslCryptoTransform(this, false, rgbKey, rgbIV);
                }
            }
            catch (CryptographicException)
            {
            }

            using (var r = this.Fallback())
            {
                return r.CreateDecryptor(rgbKey, rgbIV);
            }
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            try
            {
                if (BlockSize == 128)
                {
                    return new OpenSslCryptoTransform(this, true, rgbKey, rgbIV);
                }
            }
            catch (CryptographicException)
            {
            }

            using (var r = this.Fallback())
            {
                return r.CreateEncryptor(rgbKey, rgbIV);
            }
        }

        private Rijndael Fallback()
        {
            Rijndael r = new RijndaelManaged();
            r.Mode = Mode;
            r.Padding = Padding;
            r.BlockSize = BlockSize;
            return r;
        }
	}
}";
		string filename = Path.Combine (OutputDirectory,
			String.Format ("{0}OpenSsl.g.cs", name));
		string content = template.Replace ("{0}", name).
			Replace ("{1}", fallback).
			Replace ("{2}", ecb).
			Replace ("{3}", cbc).
			Replace ("{4}", name.ToUpperInvariant ());
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
		GenerateSymmetricAlgorithm ("Rijndael", "RijndaelManaged", "AES_ECB", "AES_CBC");
		GenerateSymmetricAlgorithm ("Aes", "RijndaelManaged", "AES_ECB", "AES_CBC");
#if UNTESTED
		GenerateSymmetricAlgorithm ("Des", "DESCryptoServiceProvider", null, "DES_CBC");
		GenerateSymmetricAlgorithm ("TripleDes", "TripleDESCryptoServiceProvider", null, "3DES_CBC");
		// BLF (Blowfish), CAST, SKIPJACK and Camellia are not part of the .NET framework 
		// and would require a additional base classes and fallbacks
#endif
	}
}
