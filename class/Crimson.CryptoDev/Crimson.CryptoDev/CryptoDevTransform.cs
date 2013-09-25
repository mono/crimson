//
// Author: 
//	Sebastien Pouliot  <sebastien@gmail.com>
// 
// Copyright 2012 Symform Inc.
//
// This code is based on:

//
// Mono.Security.Cryptography.SymmetricTransform implementation
//
// Authors:
//	Thomas Neidhart (tome@sbox.tugraz.at)
//	Sebastien Pouliot <sebastien@ximian.com>
//
// Portions (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004-2008 Novell, Inc (http://www.novell.com)
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
using Crimson.Common;

using Mono.Security.Cryptography;

namespace Crimson.CryptoDev {

	unsafe class CryptoDevTransform : CryptoTransformBase {
		Crypt context;
		byte[] save_iv;

		public CryptoDevTransform (SymmetricAlgorithm algo, Cipher cipher, bool encryption, byte[] rgbKey, byte[] rgbIV, int bufferBlockSize)
			: base(algo, encryption, rgbKey, rgbIV)

		{
			if (!Helper.IsAvailable (cipher))
				throw new CryptographicException (String.Format ("{0} not available from /dev/crypto", algo));

			// linux does not requires cloning the file descriptor with CRIOGET
			Session sess = new Session ();
			sess.cipher = cipher;
			sess.keylen = (uint) rgbKey.Length;
			fixed (byte* k = &rgbKey [0]) {
				sess.key = (IntPtr) k;
				try {
					if (Helper.SessionOp (ref sess) < 0)
						throw new CryptographicException (Marshal.GetLastWin32Error ());
				}
				finally {
					sess.key = IntPtr.Zero;
				}
			}

			context.ses = sess.ses;
			context.op = encryption ? CryptoOperation.Encrypt : CryptoOperation.Decrypt;
			// CryptoOperation constants differs in OCF (0 is None, ...)
			if (Helper.Mode == KernelMode.Ocf)
				context.op++;
			
			if (algo.Mode != CipherMode.ECB) {
				save_iv = new byte [BlockSizeByte];
			}

			// change this value if the driver (e.g. mv_cesa) has a limit that 
			// it can process in a single shot (e.g. 1936 for AES)
			BufferBlockSize = bufferBlockSize;
		}

		protected override void Dispose (bool disposing) 
		{
			if (context.ses != 0) {
				Helper.CloseSession (ref context.ses);
			}
		}

		public int BufferBlockSize {
			get; set;
		}

		protected override void Transform (byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
		{
			while (length > 0) {
				int size = Math.Min (length, BufferBlockSize);
				fixed (byte *v = iv)
				fixed (byte *i = &input [inputOffset])
				fixed (byte *o = &output [outputOffset]) {
					if (iv != null) {
						context.iv = (IntPtr) v;

						if (!encrypt) {
							int ivOffset = inputOffset + size - BlockSizeByte;
							Buffer.BlockCopy (input, ivOffset, save_iv, 0, BlockSizeByte);
						}
					}

					context.len = (uint) size;
					context.src = (IntPtr) i;
					context.dst = (IntPtr) o;
					try {
						if (Helper.CryptOp (ref context) < 0)
							throw new CryptographicException (Marshal.GetLastWin32Error ());
					}
					finally {
						context.iv = IntPtr.Zero;
						context.src = IntPtr.Zero;
						context.dst = IntPtr.Zero;
					}
				}

				if (iv != null) {
					if (encrypt)
						Buffer.BlockCopy (output, outputOffset + size - BlockSizeByte, iv, 0, BlockSizeByte);
					else
						Buffer.BlockCopy (save_iv, 0, iv, 0, BlockSizeByte);
				}

				length -= size;
				inputOffset += size;
				outputOffset += size;
			}
		}
	}
}
