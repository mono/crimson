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
	
	public class RijndaelSelector : Rijndael {
		
		SymmetricAlgorithm cipher;
		
		public RijndaelSelector ()
		{
			cipher = AlgorithmSelector.GetSymmetricAlgorithm ("Rijndael");
		}
		
		public override int BlockSize { 
			get { return cipher.BlockSize; }
			set { cipher.BlockSize = value; }
		}

		public override int FeedbackSize {
			get { return cipher.FeedbackSize; }
			set { cipher.FeedbackSize = value; }
		}

		public override byte[] IV {
			get { return cipher.IV; }
			set { cipher.IV = value; }
		}

		public override byte[] Key {
			get { return cipher.Key; }
			set { cipher.Key = value; }
		}

		public override int KeySize {
			get { return cipher.KeySize; }
			set { cipher.KeySize = value; }
		}

		public override KeySizes[] LegalBlockSizes {
			get { return cipher.LegalBlockSizes; }
		}

		public override KeySizes[] LegalKeySizes {
			get { return cipher.LegalKeySizes; }
		}

		public override CipherMode Mode {
			get { return cipher.Mode; }
			set { cipher.Mode = value; }
		}

		public override PaddingMode Padding {
			get { return cipher.Padding; }
			set { cipher.Padding = value; }
		}


		protected override void Dispose (bool disposing)
		{
			cipher.Clear ();
		}

		public override ICryptoTransform CreateDecryptor ()
		{
			return cipher.CreateDecryptor ();
		}

		public override ICryptoTransform CreateDecryptor (byte[] rgbKey, byte[] rgbIV)
		{
			return cipher.CreateDecryptor (rgbKey, rgbIV);
		}

		public override ICryptoTransform CreateEncryptor ()
		{
			return cipher.CreateEncryptor ();
		}
		
		public override ICryptoTransform CreateEncryptor (byte[] rgbKey, byte[] rgbIV)
		{
			return cipher.CreateEncryptor (rgbKey, rgbIV);
		}

		public override void GenerateIV ()
		{
			cipher.GenerateIV ();
		}
		
		public override void GenerateKey ()
		{
			cipher.GenerateKey ();
		}
		
		public override string ToString ()
		{
			 return cipher.ToString ();
		}
	}
}
