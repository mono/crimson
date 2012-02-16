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

using Mono.Security.Cryptography;

namespace Crimson.CryptoDev {

	unsafe class CryptoDevTransform : ICryptoTransform {
		bool encrypt;
		int BlockSizeByte;
		byte[] workBuff;
		bool lastBlock;
		Crypt context;
		PaddingMode padding;
		byte[] iv;
		byte[] save_iv;

		public CryptoDevTransform (SymmetricAlgorithm algo, Cipher cipher, bool encryption, byte[] rgbKey, byte[] rgbIV, int bufferBlockSize) 
		{
			if (!Helper.CryptoDevAvailable)
				throw new CryptographicException ("Cannot access /dev/crypto");

			if (rgbKey == null)
				throw new CryptographicException ("Invalid (null) key");

			BlockSizeByte = (algo.BlockSize >> 3);

			if (rgbIV == null) {
				rgbIV = KeyBuilder.IV (BlockSizeByte);
			} else {
				// compare the IV length with the "currently selected" block size and *ignore* IV that are too big
				if (rgbIV.Length < BlockSizeByte) {
					string msg = Locale.GetText ("IV is too small ({0} bytes), it should be {1} bytes long.",
						rgbIV.Length, BlockSizeByte);
					throw new CryptographicException (msg);
				}
				rgbIV = (byte[]) rgbIV.Clone ();
			}

			encrypt = encryption;
			padding = algo.Padding;

			// linux does not requires cloning the file descriptor with CRIOGET
			Session sess = new Session ();
			sess.cipher = cipher;
			sess.keylen = (uint) rgbKey.Length;
			fixed (byte* k = &rgbKey [0])
				sess.key = (IntPtr) k;

			if (Helper.SessionOp (ref sess) < 0)
				throw new CryptographicException (Marshal.GetLastWin32Error ());

			context.ses = sess.ses;
			context.op = encryption ? CryptoOperation.Encrypt : CryptoOperation.Decrypt;
			if (algo.Mode != CipherMode.ECB) {
				iv = rgbIV;
				save_iv = new byte [BlockSizeByte];
				fixed (byte* i = &iv [0])
					context.iv = (IntPtr) i;
			}

			// transform buffer
			workBuff = new byte [BlockSizeByte];
			// change this value if the driver (e.g. mv_cesa) has a limit that 
			// it can process in a single shot (e.g. 1936 for AES)
			BufferBlockSize = bufferBlockSize;
		}

		~CryptoDevTransform () 
		{
			Dispose (false);
		}

		void IDisposable.Dispose () 
		{
			Dispose (true);
		}

		protected virtual void Dispose (bool disposing) 
		{
			if (context.ses != 0) {
				Helper.CloseSession (ref context.ses);
				GC.SuppressFinalize (this);
			}
		}

		public int BufferBlockSize {
			get; set;
		}

		public virtual bool CanTransformMultipleBlocks {
			get { return true; }
		}

		public virtual bool CanReuseTransform {
			get { return false; }
		}

		public virtual int InputBlockSize {
			get { return BlockSizeByte; }
		}

		public virtual int OutputBlockSize {
			get { return BlockSizeByte; }
		}

		void Transform (byte[] input, int inputOffset, byte[] output, int outputOffset, int length)
		{
			while (length > 0) {
				int size = Math.Min (length, BufferBlockSize);
				if (iv != null) {
					fixed (byte *i = &iv [0])
						context.iv = (IntPtr) i;

					if (!encrypt)
						Buffer.BlockCopy (input, length - BlockSizeByte, save_iv, 0, BlockSizeByte);
				}

				fixed (byte *i = &input [inputOffset])
				fixed (byte *o = &output [outputOffset]) {
					context.len = (uint) size;
					context.src = (IntPtr) i;
					context.dst = (IntPtr) o;
				}

				if (Helper.CryptOp (ref context) < 0)
					throw new CryptographicException (Marshal.GetLastWin32Error ());

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

		private void CheckInput (byte[] inputBuffer, int inputOffset, int inputCount)
		{
			if (inputBuffer == null)
				throw new ArgumentNullException ("inputBuffer");
			if (inputOffset < 0)
				throw new ArgumentOutOfRangeException ("inputOffset", "< 0");
			if (inputCount < 0)
				throw new ArgumentOutOfRangeException ("inputCount", "< 0");
			// ordered to avoid possible integer overflow
			if (inputOffset > inputBuffer.Length - inputCount)
				throw new ArgumentException ("inputBuffer", Locale.GetText ("Overflow"));
		}

		// this method may get called MANY times so this is the one to optimize
		public virtual int TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset) 
		{
			CheckInput (inputBuffer, inputOffset, inputCount);
			// check output parameters
			if (outputBuffer == null)
				throw new ArgumentNullException ("outputBuffer");
			if (outputOffset < 0)
				throw new ArgumentOutOfRangeException ("outputOffset", "< 0");

			// ordered to avoid possible integer overflow
			int len = outputBuffer.Length - inputCount - outputOffset;
			if (!encrypt && (0 > len) && ((padding == PaddingMode.None) || (padding == PaddingMode.Zeros))) {
				throw new CryptographicException ("outputBuffer", Locale.GetText ("Overflow"));
			} else if (KeepLastBlock) {
				if (0 > len + BlockSizeByte) {
					throw new CryptographicException ("outputBuffer", Locale.GetText ("Overflow"));
				}
			} else {
				if (0 > len) {
					// there's a special case if this is the end of the decryption process
					if (inputBuffer.Length - inputOffset - outputBuffer.Length == BlockSizeByte)
						inputCount = outputBuffer.Length - outputOffset;
					else
						throw new CryptographicException ("outputBuffer", Locale.GetText ("Overflow"));
				}
			}
			return InternalTransformBlock (inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
		}

		private bool KeepLastBlock {
			get {
				return ((!encrypt) && (padding != PaddingMode.None) && (padding != PaddingMode.Zeros));
			}
		}

		private int InternalTransformBlock (byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset) 
		{
			int offs = inputOffset;
			int full;

			// this way we don't do a modulo every time we're called
			// and we may save a division
			if (inputCount != BlockSizeByte) {
				if ((inputCount % BlockSizeByte) != 0)
					throw new CryptographicException ("Invalid input block size.");

				full = inputCount / BlockSizeByte;
			} else
				full = 1;

			if (KeepLastBlock)
				full--;

			int total = 0;

			if (lastBlock) {
				Transform (workBuff, 0, outputBuffer, outputOffset, BlockSizeByte);
				outputOffset += BlockSizeByte;
				total += BlockSizeByte;
				lastBlock = false;
			}

			if (full > 0) {
				int length = full * BlockSizeByte;
				Transform (inputBuffer, offs, outputBuffer, outputOffset, length);
				offs += length;
				outputOffset += length;
				total += length;
			}

			if (KeepLastBlock) {
				Buffer.BlockCopy (inputBuffer, offs, workBuff, 0, BlockSizeByte);
				lastBlock = true;
			}

			return total;
		}

		RandomNumberGenerator _rng;

		private void Random (byte[] buffer, int start, int length)
		{
			if (_rng == null) {
				_rng = RandomNumberGenerator.Create ();
			}
			byte[] random = new byte [length];
			_rng.GetBytes (random);
			Buffer.BlockCopy (random, 0, buffer, start, length);
		}

		private void ThrowBadPaddingException (PaddingMode padding, int length, int position)
		{
			string msg = String.Format (Locale.GetText ("Bad {0} padding."), padding);
			if (length >= 0)
				msg += String.Format (Locale.GetText (" Invalid length {0}."), length);
			if (position >= 0)
				msg += String.Format (Locale.GetText (" Error found at position {0}."), position);
			throw new CryptographicException (msg);
		}

		private byte[] FinalEncrypt (byte[] inputBuffer, int inputOffset, int inputCount) 
		{
			// are there still full block to process ?
			int full = (inputCount / BlockSizeByte) * BlockSizeByte;
			int rem = inputCount - full;
			int total = full;

			switch (padding) {
			case PaddingMode.ANSIX923:
			case PaddingMode.ISO10126:
			case PaddingMode.PKCS7:
				// we need to add an extra block for padding
				total += BlockSizeByte;
				break;
			default:
				if (inputCount == 0)
					return new byte [0];
				if (rem != 0) {
					if (padding == PaddingMode.None)
						throw new CryptographicException ("invalid block length");
					// zero padding the input (by adding a block for the partial data)
					byte[] paddedInput = new byte [full + BlockSizeByte];
					Buffer.BlockCopy (inputBuffer, inputOffset, paddedInput, 0, inputCount);
					inputBuffer = paddedInput;
					inputOffset = 0;
					inputCount = paddedInput.Length;
					total = inputCount;
				}
				break;
			}

			byte[] res = new byte [total];
			int outputOffset = 0;

			// process all blocks except the last (final) block
			while (total > BlockSizeByte) {
				InternalTransformBlock (inputBuffer, inputOffset, BlockSizeByte, res, outputOffset);
				inputOffset += BlockSizeByte;
				outputOffset += BlockSizeByte;
				total -= BlockSizeByte;
			}

			// now we only have a single last block to encrypt
			byte pad = (byte) (BlockSizeByte - rem);
			switch (padding) {
			case PaddingMode.ANSIX923:
				// XX 00 00 00 00 00 00 07 (zero + padding length)
				res [res.Length - 1] = pad;
				Buffer.BlockCopy (inputBuffer, inputOffset, res, full, rem);
				// the last padded block will be transformed in-place
				InternalTransformBlock (res, full, BlockSizeByte, res, full);
				break;
			case PaddingMode.ISO10126:
				// XX 3F 52 2A 81 AB F7 07 (random + padding length)
				Random (res, res.Length - pad, pad - 1);
				res [res.Length - 1] = pad;
				Buffer.BlockCopy (inputBuffer, inputOffset, res, full, rem);
				// the last padded block will be transformed in-place
				InternalTransformBlock (res, full, BlockSizeByte, res, full);
				break;
			case PaddingMode.PKCS7:
				// XX 07 07 07 07 07 07 07 (padding length)
				for (int i = res.Length; --i >= (res.Length - pad);) 
					res [i] = pad;
				Buffer.BlockCopy (inputBuffer, inputOffset, res, full, rem);
				// the last padded block will be transformed in-place
				InternalTransformBlock (res, full, BlockSizeByte, res, full);
				break;
			default:
				InternalTransformBlock (inputBuffer, inputOffset, BlockSizeByte, res, outputOffset);
				break;
			}
			return res;
		}

		private byte[] FinalDecrypt (byte[] inputBuffer, int inputOffset, int inputCount) 
		{
			if ((inputCount % BlockSizeByte) > 0)
				throw new CryptographicException ("Invalid input block size.");

			int total = inputCount;
			if (lastBlock)
				total += BlockSizeByte;

			byte[] res = new byte [total];
			int outputOffset = 0;

			while (inputCount > 0) {
				int len = InternalTransformBlock (inputBuffer, inputOffset, BlockSizeByte, res, outputOffset);
				inputOffset += BlockSizeByte;
				outputOffset += len;
				inputCount -= BlockSizeByte;
			}

			if (lastBlock) {
				Transform (workBuff, 0, res, outputOffset, BlockSizeByte);
				outputOffset += BlockSizeByte;
				lastBlock = false;
			}

			// total may be 0 (e.g. PaddingMode.None)
			byte pad = ((total > 0) ? res [total - 1] : (byte) 0);
			switch (padding) {
			case PaddingMode.ANSIX923:
				if ((pad == 0) || (pad > BlockSizeByte))
					ThrowBadPaddingException (padding, pad, -1);
				for (int i = pad - 1; i > 0; i--) {
					if (res [total - 1 - i] != 0x00)
						ThrowBadPaddingException (padding, -1, i);
				}
				total -= padding;
				break;
			case PaddingMode.ISO10126:
				if ((pad == 0) || (pad > BlockSizeByte))
					ThrowBadPaddingException (padding, pad, -1);
				total -= padding;
				break;
			case PaddingMode.PKCS7:
				if ((pad == 0) || (pad > BlockSizeByte))
					ThrowBadPaddingException (padding, pad, -1);
				for (int i = pad - 1; i > 0; i--) {
					if (res [total - 1 - i] != pad)
						ThrowBadPaddingException (padding, -1, i);
				}
				total -= padding;
				break;
			case PaddingMode.None:	// nothing to do - it's a multiple of block size
			case PaddingMode.Zeros:	// nothing to do - user must unpad himself
				break;
			}

			// return output without padding
			if (total > 0) {
				byte[] data = new byte [total];
				Buffer.BlockCopy (res, 0, data, 0, total);
				// zeroize decrypted data (copy with padding)
				Array.Clear (res, 0, res.Length);
				return data;
			}
			else
				return new byte [0];
		}

		public virtual byte[] TransformFinalBlock (byte[] inputBuffer, int inputOffset, int inputCount) 
		{
			CheckInput (inputBuffer, inputOffset, inputCount);

			if (encrypt)
				return FinalEncrypt (inputBuffer, inputOffset, inputCount);
			else
				return FinalDecrypt (inputBuffer, inputOffset, inputCount);
		}
	}
}
