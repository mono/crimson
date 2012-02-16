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

	// hide platform differences, e.g. 32/64 bits
	static unsafe class Helper {

		// shared file descriptor
		static int fildes = Helper.open ("/dev/crypto", 2 /* O_RDWR */);

		static public bool CryptoDevAvailable {
			get { return (fildes != -1); }
		}

		// size will vary for 32/64 bits
		static ulong CIOCGSESSION = Ioctl.IOWR ('c', 102, sizeof (Session));
		static ulong CIOCFSESSION = Ioctl.IOW ('c', 103, sizeof (UInt32));
		static ulong CIOCCRYPT = Ioctl.IOWR ('c', 104, sizeof (Crypt));

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

		static public int SessionOp (ref Session session)
		{
			if (IntPtr.Size == 4)
				return ioctl32 (fildes, (int) CIOCGSESSION, ref session);
			else
				return ioctl64 (fildes, CIOCGSESSION, ref session);
		}

		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl32 (int fdc, int request, ref UInt32 session);
		[DllImport ("libc", SetLastError=true, EntryPoint="ioctl")]
		static extern int ioctl64 (int fdc, ulong request, ref UInt32 session);

		static public int CloseSession (ref UInt32 session)
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

		static public int CryptOp (ref Crypt crypt)
		{
			if (IntPtr.Size == 4)
				return ioctl32 (fildes, (int) CIOCCRYPT, ref crypt);
			else
				return ioctl64 (fildes, CIOCCRYPT, ref crypt);
		}
	}
}
