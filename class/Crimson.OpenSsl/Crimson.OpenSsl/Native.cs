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

namespace Crimson.OpenSsl {
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// Documentation can be found here: http://www.openssl.org/docs/crypto/EVP_DigestInit.html
    /// </summary>
    internal static class Native {
        const string DllName = "libcrypto";

        public static int ExpectSuccess (int ret) {
            if (ret <= 0) {
                throw new CryptographicException ();
            }

            return ret;
        }

        //
        // Version
        //

        [Serializable]
        public enum SSLeayVersionType {
            SSLEAY_VERSION = 0,
            SSLEAY_CFLAGS = 2,
            SSLEAY_BUILT_ON = 3,
            SSLEAY_PLATFORM = 4,
            SSLEAY_DIR = 5,
        }

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false, CharSet = CharSet.Ansi)]
        [return: MarshalAs (UnmanagedType.LPStr)]
        public extern static string SSLeay_version (SSLeayVersionType type);

        //
        // Digests
        //

        public const int MaximumDigestSize = 64;

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeDigestHandle EVP_md5 ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeDigestHandle EVP_sha1 ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeDigestHandle EVP_sha256 ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeDigestContextHandle EVP_MD_CTX_create ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        private extern static void EVP_MD_CTX_destroy (IntPtr ctx);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_DigestInit_ex (SafeDigestContextHandle ctx, SafeDigestHandle type, IntPtr impl);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_DigestUpdate (SafeDigestContextHandle ctx, IntPtr d, uint cnt);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_DigestFinal_ex (SafeDigestContextHandle ctx, IntPtr md, out uint s);

        internal sealed class SafeDigestHandle : SafeHandleZeroOrMinusOneIsInvalid {
            private SafeDigestHandle () :
                base (false) {
            }

            protected override bool ReleaseHandle () {
                return false;
            }
        }

        internal sealed class SafeDigestContextHandle : SafeHandleZeroOrMinusOneIsInvalid {
            internal SafeDigestContextHandle (IntPtr handle, bool ownsHandle) :
                base(ownsHandle) {
                this.SetHandle(handle);
            }

            private SafeDigestContextHandle () :
                base (true) {
            }

            protected override bool ReleaseHandle () {
                EVP_MD_CTX_destroy (this.handle);
                return true;
            }
        }

        //
        // Ciphers
        //

        [Serializable]
        public enum CipherOperation {
            Unchanged = -1,
            Decrypt = 0,
            Encrypt = 1,
        }

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherHandle EVP_aes_128_cbc ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherHandle EVP_aes_192_cbc ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherHandle EVP_aes_256_cbc ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherHandle EVP_aes_128_ecb ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherHandle EVP_aes_192_ecb ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherHandle EVP_aes_256_ecb ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static SafeCipherContextHandle EVP_CIPHER_CTX_new ();

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        private extern static void EVP_CIPHER_CTX_free (IntPtr a);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_CIPHER_CTX_set_key_length (SafeCipherContextHandle x, int keylen);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_CIPHER_CTX_set_padding (SafeCipherContextHandle x, int padding);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_CipherInit_ex (SafeCipherContextHandle ctx, SafeCipherHandle type, IntPtr impl, IntPtr key, IntPtr iv, CipherOperation enc);

        [DllImport (DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public extern static int EVP_CipherUpdate (SafeCipherContextHandle ctx, IntPtr outb, out int outl, IntPtr inb, int inl);

        internal sealed class SafeCipherHandle : SafeHandleZeroOrMinusOneIsInvalid {
            private SafeCipherHandle () :
                base (false) {
            }

            protected override bool ReleaseHandle () {
                return false;
            }
        }

        internal sealed class SafeCipherContextHandle : SafeHandleZeroOrMinusOneIsInvalid {
            internal SafeCipherContextHandle (IntPtr handle, bool ownsHandle) :
                base (ownsHandle) {
                this.SetHandle(handle);
            }

            private SafeCipherContextHandle () :
                base (true) {
            }

            protected override bool ReleaseHandle () {
                EVP_CIPHER_CTX_free (this.handle);
                return true;
            }
        }
    }
}
