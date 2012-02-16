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
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Crimson.CryptoDev {

	// from cryptodev.h

	// CRYPTO_*
	enum Cipher : uint {
		SHA1 = 14,
		SHA256 = 103,
		// ciphers
		AES_CBC = 11,
		AES_ECB = 23
	}

	// session_op
	struct Session {
		public Cipher	cipher;
		public Cipher	mac;
		public uint	keylen;
		public IntPtr	key;		// 32/64 bits size diff
		public uint	mackeylen;
		public IntPtr	mackey;		// 32/64 bits size diff
		public uint	ses;
#if DEBUG
		public override string ToString ()
		{
			return String.Format ("{0} {1} {2} {3} {4} {5} {6}",
				cipher, mac, keylen, key, mackeylen, mackey, ses);
		}
#endif
	}

	// COP_*
	enum CryptoOperation : ushort {
		Encrypt,	// 0
		Decrypt		// 1
	}

	// COP_FLAG_*
	[Flags]
	enum CryptoFlags : ushort {
		None = 0,
		Update = 1,
		Final = 2,
		WriteIv = 4
	}

	// crypt_op
	struct Crypt {
		public uint		ses;
		public CryptoOperation	op;
		public CryptoFlags	flags;
		public uint		len;
		public IntPtr		src;	// 32/64 bits size diff
		public IntPtr		dst;	// 32/64 bits size diff
		public IntPtr		mac;	// 32/64 bits size diff
		public IntPtr		iv;	// 32/64 bits size diff
#if DEBUG
		public override string ToString ()
		{
			return String.Format ("{0} {1} {2} {3} {4} {5} {6} {7}",
				ses, op, flags, len, src, dst, mac, iv);
		}
#endif
	}
}
