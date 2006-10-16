//
// Crimson.MHash.MHashId enumeation
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

namespace Crimson.MHash {

	internal enum MHashId {
		Crc32 = 0,
		Md5 = 1,
		Sha1 = 2,
		Haval256 = 3,
		Ripemd160 = 5,
		Tiger192 = 7,
		Gost = 8,
		Crc32b = 9,
		Haval224 = 10,
		Haval192 = 11,
		Haval160 = 12,
		Haval128 = 13,
		Tiger128 = 14,
		Tiger160 = 15,
		Md4 = 16,
		Sha256 = 17,
		Adler32 = 18,
		Sha224 = 19,
		Sha512 = 20,
		Sha384 = 21,
		Whirlpool = 22,
		Ripemd128 = 23,
		Ripemd256 = 24,
		Ripemd320 = 25,
		Snefru128 = 26,
		Snefru256 = 27,
		Md2 = 28
		// other values are defined but aren't implemented inside libmhash
	}
}
