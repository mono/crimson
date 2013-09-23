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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Crimson.CryptoDev {

	public enum KernelMode {
		Unknown = -1,
		NotAvailable = 0,
		CryptoDev = 1,
		Ocf = 2
	}
	
	// hide platform differences, e.g. 32/64 bits
	public static unsafe class Helper {
		
		// shared file descriptor
		static int fildes = -1;
		static KernelMode mode;
		static Cipher sha256;
		
		static Helper ()
		{
			try {
				fildes = Helper.open ("/dev/crypto", 2 /* O_RDWR */);
				mode = (fildes == -1) ? KernelMode.NotAvailable : KernelMode.Unknown;
			}
			catch (DllNotFoundException) {
				// libc is not available on Windows (e.g. MS.NET) and we
				// do not want to crash with a TypeInitializationException
				mode = KernelMode.NotAvailable;
			}
		}
		
		static public KernelMode Mode { 
			get { return mode; }
			private set {
				switch (value) {
				case KernelMode.CryptoDev:
					CIOCGSESSION = CD_CIOCGSESSION;
					CIOCFSESSION = CD_CIOCFSESSION;
					CIOCCRYPT = CD_CIOCCRYPT;
					break;
				case KernelMode.Ocf:
					CIOCGSESSION = OCF_CIOCGSESSION;
					CIOCFSESSION = OCF_CIOCFSESSION;
					CIOCCRYPT = OCF_CIOCCRYPT;
					break;
				default:
					throw new InvalidOperationException ();
				}
				mode = value;
			}
		}
		
		static byte[] null_key = new byte [32]; // 128 bit key
		
		// cryptodev can be available but may not support the algorithm
		// we wish to use (and we must fallback to another implementation)
		static public bool IsCryptoDev (Cipher algo)
		{
			if (Mode == KernelMode.NotAvailable)
				return false;
			return Is (algo, KernelMode.CryptoDev);
		}

		static public bool IsOcf (Cipher algo)
		{
			if (Mode == KernelMode.NotAvailable)
				return false;
			return Is (algo, KernelMode.Ocf);
		}
		
		// note: calling IsAvailable ensure 'mode' is set and makes 
		// every implementations works properly
		static public bool IsAvailable (Cipher algo)
		{
			if (Mode == KernelMode.NotAvailable)
				return false;
			if (Is (algo, KernelMode.CryptoDev))
				return true;
			return Is (algo, KernelMode.Ocf);
		}

		static HashSet<long> availability = new HashSet<long> ();
		
		static bool Is (Cipher algo, KernelMode mode)
		{
			// asking the kernel for availability turns out to be very costly
			long key = (((long) algo << 32) | (long) mode);
			if (availability.Contains (key))
				return true;

			bool result = false;
			Session session = new Session ();
			fixed (byte* k = &null_key [0]) {
				switch (algo) {
				case Cipher.AES_CBC:
				case Cipher.AES_ECB:
					session.cipher = algo;
					session.keylen = 32;
					session.key = (IntPtr)k;
					break;
				case Cipher.SHA1:
					session.mac = algo;
					break;
				// accept both SHA256 and SHA2_256 and use the correct one
				case Cipher.SHA256:
				case Cipher.SHA2_256:
					if (mode == KernelMode.Ocf)
						session.mac = Cipher.SHA2_256;
					else
						session.mac = IsNewCryptoDev() ? Cipher.SHA256_NEW : Cipher.SHA256;
					// save the result
					sha256 = session.mac;
					break;
				default:
					return false;
				}

				ulong ciocgsession = mode == KernelMode.CryptoDev ? CD_CIOCGSESSION : OCF_CIOCGSESSION;
				if (IntPtr.Size == 4)
					result = ioctl32 (fildes, (int) ciocgsession, ref session) == 0;
				else
					result = ioctl64 (fildes, ciocgsession, ref session) == 0;
			}
			if (result) {
				CloseSession(ref session.ses);
				Mode = mode;
				availability.Add (key);
			}
			return result;
		}
		
		static bool IsNewCryptoDev ()
		{
			// check if this is a new crypto dev module by testing for SHA2_224_HMAC.
			// see discussion here https://github.com/nmav/cryptodev-linux/commit/d87ab5584893d06a21fe7cbf6e052d6757f9aa91#diff-535166266eead3c57bed2059c5006818
			Session session = new Session ();
			session.mac = (Cipher)107; // CRYPTO_SHA2_224_HMAC
			bool result;
			if (IntPtr.Size == 4)
				result = ioctl32 (fildes, (int)CD_CIOCGSESSION, ref session) == 0;
			else
				result = ioctl64 (fildes, CD_CIOCGSESSION, ref session) == 0;
			if (result) {
				CloseSession(ref session.ses);
			}
			return result;
		}

		// values varies for cryptodev and OCF and for 32/64 bits
		static ulong CIOCGSESSION = 0;
		static ulong CIOCFSESSION = 0;
		static ulong CIOCCRYPT = 0;
		
		// cryptodev constants : size will vary for 32/64 bits
		static ulong CD_CIOCGSESSION = Ioctl.IOWR ('c', 102, sizeof (CryptoDevSession));
		static ulong CD_CIOCFSESSION = Ioctl.IOW ('c', 103, sizeof (UInt32));
		static ulong CD_CIOCCRYPT = Ioctl.IOWR ('c', 104, sizeof (Crypt));
		
		// OCF constants : size will vary for 32/64 bits
		static ulong OCF_CIOCGSESSION = Ioctl.IOWR ('c', 106, sizeof (Session));
		static ulong OCF_CIOCFSESSION = Ioctl.IOW ('c', 102, sizeof (UInt32));
		static ulong OCF_CIOCCRYPT = Ioctl.IOWR ('c', 103, sizeof (Crypt));

		[DllImport ("libc", SetLastError=true, EntryPoint="open")]
		static public extern int open (string path, int oflag);

		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl32 (int fd, int request, ref int fdc);
		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl64 (int fd, ulong request, ref int fdc);

		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl32 (int fdc, int request, ref Session session);
		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl64 (int fdc, ulong request, ref Session session);

		static internal int SessionOp (ref Session session)
		{
			if (session.mac == Cipher.SHA256)
				session.mac = sha256;
				
			if (IntPtr.Size == 4)
				return ioctl32 (fildes, (int) CIOCGSESSION, ref session);
			else
				return ioctl64 (fildes, CIOCGSESSION, ref session);
		}

		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl32 (int fdc, int request, ref UInt32 session);
		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl64 (int fdc, ulong request, ref UInt32 session);

		static internal int CloseSession (ref UInt32 session)
		{
			int result = -1;
			if (IntPtr.Size == 4)
				result = ioctl32 (fildes, (int) CIOCFSESSION, ref session);
			else
				result = ioctl64 (fildes, CIOCFSESSION, ref session);
			session = 0;
			return result;
		}

		[DllImport ("libc", SetLastError=true, EntryPoint="close")]
		static public extern int close (int filedes);

		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl32 (int fd, int request, ref Crypt crypt);
		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl64 (int fd, ulong request, ref Crypt crypt);

		static internal int CryptOp (ref Crypt crypt)
		{
			if (IntPtr.Size == 4)
				return ioctl32 (fildes, (int) CIOCCRYPT, ref crypt);
			else
				return ioctl64 (fildes, CIOCCRYPT, ref crypt);
		}
	}
}
