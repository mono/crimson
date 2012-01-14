//
// HashAlgorithmTest.cs - NUnit Test Cases for HashAlgorithm
//
// Author:
//	Sebastien Pouliot  <sebastien@xamarin.com>
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) 2004, 2006, 2007 Novell, Inc (http://www.novell.com)
// Copyright 2012 Xamarin Inc. (http://www.xamarin.com)
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

using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crimson.Test.Base {

	public class HashAlgorithmTest {
	
		protected HashAlgorithm hash;
	
		[Test]
		[ExpectedException (typeof (ObjectDisposedException))]
		public void Clear () 
		{
			byte[] inputABC = Encoding.Default.GetBytes ("abc");
			hash.ComputeHash (inputABC);
			hash.Clear ();
			// cannot use a disposed object
			hash.ComputeHash (inputABC);
		}
	
		[Test]
		[ExpectedException (typeof (ObjectDisposedException))]
		public void Clear2 () 
		{
			byte[] inputABC = Encoding.Default.GetBytes ("abc");
			MemoryStream ms = new MemoryStream (inputABC);
			hash.ComputeHash (ms);
			hash.Clear ();
			// cannot use a disposed object
			hash.ComputeHash (ms);
		}
	
		[Test]
		[ExpectedException (typeof (NullReferenceException))]
		public void NullStream () 
		{
			Stream s = null;
			hash.ComputeHash (s);
		}
	
		[Test]
		public void Disposable () 
		{
			using (HashAlgorithm hash = HashAlgorithm.Create ()) {
				hash.ComputeHash (new byte [0]);
			}
		}
	
		[Test]
		[ExpectedException (typeof (ObjectDisposedException))]
		public void InitializeDisposed () 
		{
			hash.ComputeHash (new byte [0]);
			hash.Clear (); // disposed
			hash.Initialize ();
			hash.ComputeHash (new byte [0]);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void ComputeHash_ArrayNull ()
		{
			byte[] array = null;
			hash.ComputeHash (array);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void ComputeHash_ArrayNullIntInt ()
		{
			byte[] array = null;
			hash.ComputeHash (array, 0, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentOutOfRangeException))]
		public void ComputeHash_OffsetNegative ()
		{
			byte[] array = new byte [0];
			hash.ComputeHash (array, -1, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void ComputeHash_OffsetOverflow ()
		{
			byte[] array = new byte [1];
			hash.ComputeHash (array, Int32.MaxValue, 1);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void ComputeHash_CountNegative ()
		{
			byte[] array = new byte [0];
			hash.ComputeHash (array, 0, -1);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void ComputeHash_CountOverflow ()
		{
			byte[] array = new byte [1];
			hash.ComputeHash (array, 1, Int32.MaxValue);
		}
	
		[Test]
	// not checked in Fx 1.1
	//	[ExpectedException (typeof (ObjectDisposedException))]
		public void TransformBlock_Disposed () 
		{
			hash.ComputeHash (new byte [0]);
			hash.Initialize ();
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, 0, input.Length, output, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void TransformBlock_InputBuffer_Null ()
		{
			byte[] output = new byte [8];
			hash.TransformBlock (null, 0, output.Length, output, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentOutOfRangeException))]
		public void TransformBlock_InputOffset_Negative ()
		{
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, -1, input.Length, output, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformBlock_InputOffset_Overflow ()
		{
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, Int32.MaxValue, input.Length, output, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformBlock_InputCount_Negative ()
		{
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, 0, -1, output, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformBlock_InputCount_Overflow ()
		{
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, 0, Int32.MaxValue, output, 0);
		}
	
		[Test]
		public void TransformBlock_OutputBuffer_Null ()
		{
			byte[] input = new byte [8];
			hash.TransformBlock (input, 0, input.Length, null, 0);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentOutOfRangeException))]
		public void TransformBlock_OutputOffset_Negative ()
		{
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, 0, input.Length, output, -1);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformBlock_OutputOffset_Overflow ()
		{
			byte[] input = new byte [8];
			byte[] output = new byte [8];
			hash.TransformBlock (input, 0, input.Length, output, Int32.MaxValue);
		}
	
		[Test]
	// not checked in Fx 1.1
	//	[ExpectedException (typeof (ObjectDisposedException))]
		public void TransformFinalBlock_Disposed () 
		{
			hash.ComputeHash (new byte [0]);
			hash.Initialize ();
			byte[] input = new byte [8];
			hash.TransformFinalBlock (input, 0, input.Length);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentNullException))]
		public void TransformFinalBlock_InputBuffer_Null ()
		{
			hash.TransformFinalBlock (null, 0, 8);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentOutOfRangeException))]
		public void TransformFinalBlock_InputOffset_Negative ()
		{
			byte[] input = new byte [8];
			hash.TransformFinalBlock (input, -1, input.Length);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformFinalBlock_InputOffset_Overflow ()
		{
			byte[] input = new byte [8];
			hash.TransformFinalBlock (input, Int32.MaxValue, input.Length);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformFinalBlock_InputCount_Negative ()
		{
			byte[] input = new byte [8];
			hash.TransformFinalBlock (input, 0, -1);
		}
	
		[Test]
		[ExpectedException (typeof (ArgumentException))]
		public void TransformFinalBlock_InputCount_Overflow ()
		{
			byte[] input = new byte [8];
			hash.TransformFinalBlock (input, 0, Int32.MaxValue);
		}
	
		[Test]
		public void TransformFinalBlock_Twice_Initialize ()
		{
			byte[] input = new byte[8];
			hash.TransformFinalBlock (input, 0, input.Length);
			hash.Initialize ();
			hash.TransformFinalBlock (input, 0, input.Length);
		}
	
		[Test]
		public void TransformFinalBlock_ReturnedBuffer ()
		{
			byte[] input = new byte[8];
			byte[] output = hash.TransformFinalBlock (input, 0, input.Length);
			Assert.AreEqual (input, output, "buffer");
			output[0] = 1;
			Assert.AreEqual (0, input[0], "0"); // output is a copy (not a reference)
		}
	
		private byte[] HashBuffer (bool intersect)
		{
			byte[] buffer = new byte [256];
			for (int i = 0; i < buffer.Length; i++)
				buffer [i] = (byte) i;
	
			hash.Initialize ();
			// ok
			hash.TransformBlock (buffer, 0, 64, buffer, 0);
			// bad - we rewrite the beginning of the buffer
			hash.TransformBlock (buffer, 64, 128, buffer, intersect ? 0 : 64);
			// ok
			hash.TransformFinalBlock (buffer, 192, 64);
			return hash.Hash;
		}
	
		[Test]
		public void InputOutputIntersection ()
		{
			Assert.AreEqual (HashBuffer (false), HashBuffer (true), "Intersect");
		}
	
		[Test]
		[ExpectedException (typeof (CryptographicUnexpectedOperationException))]
		public void Hash_AfterInitialize_SecondTime ()
		{
			byte[] input = new byte[8];
			hash.Initialize ();
			hash.TransformBlock (input, 0, input.Length, input, 0);
			hash.Initialize ();
			// getting the property throws
			Assert.IsNull (hash.Hash);
		}
	
		[Test]
		[ExpectedException (typeof (CryptographicUnexpectedOperationException))]
		public void Hash_AfterTransformBlock ()
		{
			byte[] input = new byte[8];
			hash.Initialize ();
			hash.TransformBlock (input, 0, input.Length, input, 0);
			// getting the property throws
			Assert.IsNull (hash.Hash);
		}
	
		[Test]
		public void Hash_AfterTransformFinalBlock ()
		{
			byte[] input = new byte[8];
			hash.Initialize ();
			hash.TransformFinalBlock (input, 0, input.Length);
			Assert.IsNotNull (hash.Hash);
		}
	}
}
