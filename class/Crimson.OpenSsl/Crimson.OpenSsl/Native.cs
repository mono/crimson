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
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// Documentation can be found here: http://www.openssl.org/docs/crypto/EVP_DigestInit.html
    /// </summary>
    internal class Native
    {
        const string Dllname = "libcrypto";

        public static int ExpectSuccess(int ret)
        {
            if (ret <= 0)
            {
                throw new CryptographicException();
            }

            return ret;
        }

		//
		// Version
		//

		public const int SSLEAY_VERSION = 0;
		public const int SSLEAY_CFLAGS = 2;
		public const int SSLEAY_BUILT_ON = 3;
		public const int SSLEAY_PLATFORM = 4;
		public const int SSLEAY_DIR = 5;

		[DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
		[return : MarshalAs(UnmanagedType.LPStr)]
		public extern static IntPtr SSLeay_version(int type);

        //
        // Digests
        //

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_md5();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha1();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_sha256();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_MD_CTX_create();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static void EVP_MD_CTX_destroy(IntPtr ctx);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestInit_ex(IntPtr ctx, IntPtr type, IntPtr impl);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestUpdate(IntPtr ctx, IntPtr d, uint cnt);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_DigestFinal_ex(IntPtr ctx, IntPtr md, ref uint s);

        //
        // Ciphers
        //

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_cbc();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_cbc();
        
        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_cbc();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_128_ecb();
        
        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_192_ecb();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_aes_256_ecb();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr EVP_CIPHER_CTX_new();

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_free(IntPtr a);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_set_key_length(IntPtr x, int keylen);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CIPHER_CTX_set_padding(IntPtr x, int padding);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CipherInit_ex(IntPtr ctx, IntPtr type, IntPtr impl, IntPtr key, IntPtr iv, int enc);

        [DllImport(Dllname, CallingConvention = CallingConvention.Cdecl)]
        public extern static int EVP_CipherUpdate(IntPtr ctx, IntPtr outb, out int outl, IntPtr inb, int inl);
    }
}
