//
// Author: 
//	Bassam Tabbara  <bassam@symform.com>
// 
// Copyright 2013 Symform Inc.
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
namespace Crimson.OpenSsl
{
    using System;

    public sealed class HashHelper : IDisposable
    {
        private IntPtr context;
        private readonly int hashSize;

        public HashHelper(IntPtr mdptr, int hashSize)
        {
            this.hashSize = hashSize >> 3;
            this.context = Native.EVP_MD_CTX_create();

            Native.ExpectSuccess(Native.EVP_DigestInit_ex(this.context, mdptr, IntPtr.Zero));
        }

        ~HashHelper()
        {
            Dispose();
        }

        public void Dispose()
        {
            if (this.context != IntPtr.Zero)
            {
                Native.EVP_MD_CTX_destroy(this.context);
                this.context = IntPtr.Zero;
            }

            GC.SuppressFinalize(this);
        }

        public unsafe void Update(byte[] data, int start, int length)
        {
            if (length == 0)
            {
                return;
            }

            fixed (byte* p = &data[start])
            {
                Native.ExpectSuccess(Native.EVP_DigestUpdate(this.context, (IntPtr)p, (uint)length));
            }
        }

        public unsafe byte[] Final()
        {
            var digest = new byte[this.hashSize];
            var len = (uint)digest.Length;

            fixed (byte* p = &digest[0])
            {
                Native.ExpectSuccess(Native.EVP_DigestFinal_ex(this.context, (IntPtr)p, ref len));
            }

            return digest;
        }
    }
}
