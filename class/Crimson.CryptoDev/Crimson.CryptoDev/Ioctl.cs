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

namespace Crimson.CryptoDev {

	// from ioctl.h

	class Ioctl {

		const ulong IOC_READ = 2;
		const ulong IOC_WRITE = 1;

		const int IOC_NRBITS = 8;
		const int IOC_TYPEBITS = 8;
		const int IOC_SIZEBITS = 14;
		const int IOC_DIRBITS = 2;

		const ulong IOC_NRMASK = (((ulong)1 << IOC_NRBITS)-1);
		const ulong IOC_TYPEMASK = (((ulong)1 << IOC_TYPEBITS)-1);
		const ulong IOC_SIZEMASK = (((ulong)1 << IOC_SIZEBITS)-1);
		const ulong IOC_DIRMASK = (((ulong)1 << IOC_DIRBITS)-1);

		const int IOC_NRSHIFT = 0;
		const int IOC_TYPESHIFT = (IOC_NRSHIFT + IOC_NRBITS);
		const int IOC_SIZESHIFT = (IOC_TYPESHIFT + IOC_TYPEBITS);
		const int IOC_DIRSHIFT = (IOC_SIZESHIFT + IOC_SIZEBITS);

		static ulong IOC (ulong dir, ulong type, ulong nr, ulong size)
		{
			return (((dir)  << IOC_DIRSHIFT) |
				((type) << IOC_TYPESHIFT) |
				((nr)   << IOC_NRSHIFT) |
				((size) << IOC_SIZESHIFT));
		}

		static public ulong IOWR (ulong type, ulong nr, int size)
		{
			return IOC (IOC_READ | IOC_WRITE, type, nr, (ulong) size);
		}

		static public ulong IOW (ulong type, ulong nr, int size)
		{
			return IOC (IOC_WRITE, type, nr, (ulong) size);
		}
#if TEST
		static unsafe void Main ()
		{
			// IOWR('c', 102, struct session_op)
			Console.WriteLine ("CIOCGSESSION = {0}", IOWR ('c', 102, sizeof (Session)));
			Console.WriteLine ("CIOCFSESSION = {0}", IOW ('c', 103, sizeof (System.UInt32)));
			Console.WriteLine ("CIOCCRYPT = {0}", IOWR ('c', 104, sizeof (Crypt)));
		}
#endif
	}
}
