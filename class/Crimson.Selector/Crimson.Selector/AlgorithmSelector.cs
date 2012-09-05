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
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;

namespace Crimson.Selector {
	
	static class AlgorithmSelector {
		
		struct Candidate {
			public string Name;
			public Func<Type> Try;
		}
		
		static List<Candidate> implementations = new List<Candidate> ();
		static Dictionary<string, Type> mapping = new Dictionary<string, Type> ();
		
		static AlgorithmSelector ()
		{
			// SHA1 is available on Linux with CryptoDev (OCF fails at the moment)
			implementations.Add (new Candidate () {
				Name = "SHA1",
				Try = delegate {
					if (!IsCryptoDev (SHA1))
						return null;
					return Type.GetType ("Crimson.Security.Cryptography.SHA1Kernel, Crimson.CryptoDev");
				}
			});
			// SHA256 is available on Linux with CryptoDev (but not on OCF at the moment)
			implementations.Add (new Candidate () {
				Name = "SHA256",
				Try = delegate {
					if (!IsCryptoDev (SHA256))
						return null;
					return Type.GetType ("Crimson.Security.Cryptography.SHA256Kernel, Crimson.CryptoDev");
				}
			});
			// AES-CBC is available on Linux with CryptoDev and OCF
			implementations.Add (new Candidate () {
				Name = "System.Security.Cryptography.AesManaged, System.Core",
				Try = delegate {
					if (!IsCryptoDevOrOcf (AES))
						return null;
					return Type.GetType ("Crimson.Security.Cryptography.AesKernel, Crimson.CryptoDev");
				}
			});
			implementations.Add (new Candidate () {
				Name = "Rijndael",
				Try = delegate {
					if (!IsCryptoDevOrOcf (AES))
						return null;
					// this use AES when possible (block size and mode) and fallback to managed otherwise
					return Type.GetType ("Crimson.Security.Cryptography.RijndaelKernel, Crimson.CryptoDev");
				}
			});
		}

		static object Create (string name)
		{
			Type type;
			// have we resolved the type yet ?
			if (!mapping.TryGetValue (name, out type)) {
				// no, then find the best implementation we know of
				foreach (Candidate candidate in implementations) {
					if (candidate.Name != name)
						continue;
						
					try {
						type = candidate.Try ();
						if (type != null) {
							mapping.Add (name, type);
							break;
						}
					}
					catch {
					}
				}
			}
			
			// create what/if we found
			if (type != null)
				return Activator.CreateInstance (type);
			
			// fallback to CryptoConfig's default
			object cc_default = CryptoConfig.CreateFromName (name);
			// add mapping to default so we don't iterate each time
			mapping.Add (name, cc_default.GetType ());
			return cc_default;
		}
			
		#region General Detection Helpers

		static bool IsUnix {
			get { return (Environment.OSVersion.Platform == PlatformID.Unix); }
		}
		
		#endregion
		
		#region Crimson.CryptoDev.dll Helpers
		
		const uint SHA1 = 14;
		const uint AES = 11;
		const uint SHA256 = 103;
		
		const BindingFlags StaticPublic = BindingFlags.Public | BindingFlags.Static;
		
		static MethodInfo cryptodev;
		static MethodInfo available;
		
		static void InitCryptoDev ()
		{
			Type type = Type.GetType ("Crimson.CryptoDev.Helper, Crimson.CryptoDev");
			cryptodev = type.GetMethod ("IsCryptoDev", StaticPublic);
			available = type.GetMethod ("IsAvailable", StaticPublic);
		}
		
		static bool IsCryptoDev (uint cipher)
		{
			if (!IsUnix)
				return false;
			if (cryptodev == null)
				InitCryptoDev ();
			return (bool) cryptodev.Invoke (null, new object [] { cipher });
		}

		static bool IsCryptoDevOrOcf (uint cipher)
		{
			if (!IsUnix)
				return false;
			if (cryptodev == null)
				InitCryptoDev ();
			return (bool) available.Invoke (null, new object [] { cipher });
		}
		
		#endregion
		
		#region Hash Helpers

		static BindingFlags InstanceProtected = BindingFlags.Instance | BindingFlags.NonPublic;
		
		static MethodInfo core;
		static MethodInfo final;
		
		// we can't call HashCore directly since it's a protected member
		static internal void Core (this HashAlgorithm self, object[] parameters)
		{
			core.Invoke (self, parameters);
		}
		
		// we can't call HashFinal directly since it's a protected member
		static internal byte[] Final (this HashAlgorithm self)
		{
			return (byte[]) final.Invoke (self, null);
		}
				
		static internal HashAlgorithm GetHashAlgorithm (string name)
		{
			if (core == null) {
				Type type = typeof (HashAlgorithm);
				core = type.GetMethod ("HashCore", InstanceProtected);
				final = type.GetMethod ("HashFinal", InstanceProtected);
			}
			
			return (HashAlgorithm) Create (name);
		}
		
		#endregion
		
		#region Symmetric Ciphers Helpers
		
		static internal SymmetricAlgorithm GetSymmetricAlgorithm (string name)
		{
			return (SymmetricAlgorithm) Create (name);
		}
		
		#endregion
	}
}
