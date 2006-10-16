//
// Crimson.MHash.MHashHelper class
//
// Authors:
//	Sebastien Pouliot  <sebastien@ximian.com>
//
// Copyright (C) 2006 Novell, Inc (http://www.novell.com)
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

namespace Crimson.MHash {

	internal class MHashHelper : IDisposable {

		private MHashId type;
		private IntPtr handle;
		private int blocksize;

		public MHashHelper (MHashId type)
		{
			this.type = type;
			handle = MHashWrapper.mhash_init (type);
			if (handle == IntPtr.Zero) {
				string msg = String.Format ("Unknown mhash id '{0}'.", type);
				throw new CryptographicException (msg);
			}

			blocksize = (int) MHashWrapper.mhash_get_block_size (type);
		}

		~MHashHelper ()
		{
			Dispose ();
		}

		public int BlockSize {
			get { return blocksize; }
		}

		public IntPtr Handle {
			get { return handle; }
		}

		public void Initialize ()
		{
			if (handle == IntPtr.Zero)
				GC.ReRegisterForFinalize (this);
			handle = MHashWrapper.mhash_init (type);
		}

		public void HashCore (byte[] data, int start, int length)
		{
			if (data == null)
				throw new ArgumentNullException ("data");
			if (start < 0)
				throw new ArgumentException ("start");
			if (length < 0)
				throw new ArgumentException ("length");

			if (length == 0)
				return;

			// avoid copying data unless required (API limitation)
			if (start == 0) {
				MHashWrapper.mhash (handle, data, (IntPtr)length);
			} else {
				byte[] partial = new byte [length];
				Buffer.BlockCopy (data, start, partial, 0, length);
				MHashWrapper.mhash (handle, partial, (IntPtr)length);
			}
		}

		public byte[] HashFinal ()
		{
			byte[] result = new byte [blocksize];
			IntPtr digest = MHashWrapper.mhash_end (handle);
			try {
				Marshal.Copy (digest, result, 0, blocksize);
			}
			finally {
				Marshal.FreeHGlobal (digest);
				handle = IntPtr.Zero;
			}
			return result;
		}

		public void Dispose () 
		{
			if (handle != IntPtr.Zero) {
				// this frees the hashing structure, but allocates the digest
				IntPtr digest = MHashWrapper.mhash_end (handle);
				// so we still have a second free to make to complete dispose
				Marshal.FreeHGlobal (digest);
				handle = IntPtr.Zero;
				GC.SuppressFinalize (this);
			}
		}
	}
}
