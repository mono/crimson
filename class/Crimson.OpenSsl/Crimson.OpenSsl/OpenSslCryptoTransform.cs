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
    using System.Security.Cryptography;
    using Crimson.Common;

    internal unsafe class OpenSslCryptoTransform : CryptoTransformBase
    {
        private IntPtr context;

        public OpenSslCryptoTransform(SymmetricAlgorithm algo, bool encrypt, byte[] rgbKey, byte[] rgbIV)
            : base(algo, encrypt, rgbKey, rgbIV)
        {
            this.context = Native.EVP_CIPHER_CTX_new();

            var cptr = this.GetCipher(algo.Mode, rgbKey.Length);

            fixed (byte *pkey = &rgbKey[0])
            fixed (byte* piv = &iv[0])
            {
                Native.ExpectSuccess(Native.EVP_CipherInit_ex(this.context, cptr, IntPtr.Zero, (IntPtr)pkey, (IntPtr)piv, encrypt? 1: 0));
            }

            Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_key_length(this.context, rgbKey.Length));
            Native.ExpectSuccess(Native.EVP_CIPHER_CTX_set_padding(this.context, 0));
        }

        protected override void Dispose(bool disposing)
        {
            if (this.context != IntPtr.Zero)
            {
                Native.EVP_CIPHER_CTX_free(this.context);
                this.context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        protected override void Transform(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset, int inputCount)
        {
            fixed (byte* input = &inputBuffer[inputOffset])
            fixed (byte* output = &outputBuffer[outputOffset])
            {
                int outputCount;
                Native.ExpectSuccess(Native.EVP_CipherUpdate(this.context, (IntPtr)output, out outputCount, (IntPtr)input, inputCount));
            }
        }

        private IntPtr GetCipher(CipherMode mode, int keyLength)
        {
            if (mode == CipherMode.CBC)
            {
                switch (keyLength)
                {
                    case 16:
                        return Native.EVP_aes_128_cbc();

                    case 24:
                        return Native.EVP_aes_192_cbc();

                    case 32:
                        return Native.EVP_aes_256_cbc();
                }
            }
            else if (mode == CipherMode.ECB)
            {
                switch (keyLength)
                {
                    case 16:
                        return Native.EVP_aes_128_ecb();

                    case 24:
                        return Native.EVP_aes_192_ecb();

                    case 32:
                        return Native.EVP_aes_256_ecb();
                }
            }

            throw new CryptographicException(string.Format("{0} not supported", mode));
        }
    }
}
