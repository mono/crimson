//
// Author: 
//	Bassam Tabbara  <bassam@symform.com>
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
namespace Crimson.OpenSsl
{
	using System;
	using System.Security.Cryptography;

	internal sealed class HashHelper : IDisposable
	{
		private readonly Native.SafeDigestContextHandle context;
		private readonly int hashSize;

		public HashHelper (Native.SafeDigestHandle digest, int hashSize)
		{
			this.hashSize = hashSize >> 3;
			if (this.hashSize > Native.MaximumDigestSize) {
				throw new ArgumentOutOfRangeException ("hashSize");
			}

			this.context = Native.EVP_MD_CTX_create ();
			Native.ExpectSuccess (Native.EVP_DigestInit_ex (this.context, digest, IntPtr.Zero));
		}

		public void Dispose ()
		{
			this.context.Dispose ();
		}

		public unsafe void Update (byte[] data, int start, int length)
		{
			if (start + length > data.Length) {
				throw new ArgumentOutOfRangeException ("data");
			}

			if (length == 0) {
				return;
			}

			if (length < uint.MinValue) {
				throw new ArgumentOutOfRangeException ("length");
			}

			fixed (byte* p = &data[start]) {
				Native.ExpectSuccess (Native.EVP_DigestUpdate (this.context, (IntPtr)p, (uint)length));
			}
		}

		public unsafe byte[] Final ()
		{
			var digest = new byte[Native.MaximumDigestSize];
			uint len;

			fixed (byte* p = &digest[0]) {
				Native.ExpectSuccess (Native.EVP_DigestFinal_ex (this.context, (IntPtr)p, out len));
			}

			if (len != this.hashSize) {
				throw new CryptographicException (string.Format ("Mismatched hash length was expecting {0} but got {1}", this.hashSize, len));
			}

			if (len == digest.Length) {
				return digest;
			}

			var trimmed = new byte[this.hashSize];
			Buffer.BlockCopy (digest, 0, trimmed, 0, this.hashSize);
			return trimmed;
		}
	}
}
