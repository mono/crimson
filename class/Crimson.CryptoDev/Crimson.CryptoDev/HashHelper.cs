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

	unsafe class HashHelper : IDisposable {

		Crypt context;

		public HashHelper (Cipher algo)
		{
			if (!Helper.CryptoDevAvailable)
				throw new CryptographicException ("Cannot access /dev/crypto");

			// linux does not requires cloning the file descriptor with CRIOGET
			Session sess = new Session ();
			sess.mac = algo;

			if (Helper.SessionOp (ref sess) < 0)
				throw new CryptographicException (Marshal.GetLastWin32Error ());

			context.ses = sess.ses;
			context.op = CryptoOperation.Encrypt;
			// change this value if the driver (e.g. mv_cesa) has a limit that 
			// it can process in a single shot (e.g. 1932 for SHA1)
			BufferBlockSize = Int32.MaxValue;
		}

		~HashHelper ()
		{
			Dispose ();
		}

		public int BufferBlockSize {
			get; set;
		}

		public void Dispose ()
		{
			if (context.ses != 0) {
				Helper.CloseSession (ref context.ses);
				GC.SuppressFinalize (this);
			}
		}

		public void Update (byte[] data, int start, int length)
		{
			while (length > 0) {
				int size = Math.Min (length, BufferBlockSize);
				fixed (byte* p = &data [start]) {
					context.len = (uint) size;
					context.src = (IntPtr) p;
					context.flags = CryptoFlags.Update;
				}
				if (Helper.CryptOp (ref context) < 0)
					throw new CryptographicException (Marshal.GetLastWin32Error ());
				length -= size;
				start += size;
			}
		}

		public byte[] Final (int hashSize)
		{
			byte[] digest = new byte [hashSize];
			fixed (byte* p = &digest [0]) {
				context.len = 0;
				context.src = IntPtr.Zero;
				context.mac = (IntPtr) p;
			}
			if (Helper.CryptOp (ref context) < 0)
				throw new CryptographicException (Marshal.GetLastWin32Error ());

			context.mac = IntPtr.Zero;
			return digest;
		}		
	}
}
