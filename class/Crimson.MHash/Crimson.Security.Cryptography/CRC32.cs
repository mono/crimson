/* DO NOT EDIT *** This file was generated automatically *** DO NOT EDIT */

//
// Authors:
//	Sebastien Pouliot  <sebastien@ximian.com>
//
// Copyright (C) 2006 Novell, Inc (http://www.novell.com)
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

using System;
using System.Security.Cryptography;

namespace Crimson.Security.Cryptography {

	public abstract class CRC32 : HashAlgorithm {

		protected CRC32 ()
		{
			// CRC32 digest length is 32 bits long
			HashSizeValue = 32;
		}

		public static new CRC32 Create ()
		{
			return Create ("CRC32");
		}

		public static new CRC32 Create (string hashName)
		{
			object o = CryptoConfig.CreateFromName (hashName);
			// in case machine.config isn't configured to use any CRC32 implementation
			if (o == null) {
				o = new CRC32Native ();
			}
			return (CRC32) o;
		}
	}
}/* DO NOT EDIT *** This file was generated automatically *** DO NOT EDIT */
