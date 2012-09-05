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
using System.Security.Cryptography;

using Crimson.Selector;

namespace Crimson.Security.Cryptography {
	
	public class SHA256Selector : SHA256 {
		
		HashAlgorithm hash;
		object[] parameters;
		
		public SHA256Selector ()
		{
			parameters = new object [3]; // alloc once and reuse
			hash = AlgorithmSelector.GetHashAlgorithm ("SHA256");
		}
		
		public override void Initialize ()
		{
			hash.Initialize ();
		}
		
		protected override void HashCore (byte[] rgb, int ibStart, int cbSize)
		{
			parameters [0] = rgb;
			parameters [1] = ibStart;
			parameters [2] = cbSize;
			hash.Core (parameters);
		}
		
		protected override byte[] HashFinal ()
		{
			return hash.Final ();
		}
		
		public override string ToString ()
		{
			 return hash.ToString ();
		}
	}
}
