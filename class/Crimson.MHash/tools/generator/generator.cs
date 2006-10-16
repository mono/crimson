//
// generator.cs: Libmhash wrapper generator
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
using System.IO;
using System.Text;

using Crimson.MHash;

public class Generator {

	static string header = @"/* DO NOT EDIT *** This file was generated automatically *** DO NOT EDIT */

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
";

	static string mhash_start = @"
using System;
using System.Security.Cryptography;

using Crimson.MHash;

namespace Crimson.Security.Cryptography {
";

	static string mhash_ctor = @"
		{
			hash = new MHashHelper (Id);
		}

";

	static string mhash_end = @"
		{
			Dispose ();
		}

		public void Dispose () 
		{
			if (hash.Handle != IntPtr.Zero) {
				hash.Dispose ();
				GC.SuppressFinalize (this);
			}
		}

		public override void Initialize ()
		{
			if (hash.Handle == IntPtr.Zero) {
				GC.ReRegisterForFinalize (this);
				hash.Initialize ();
			}
		}

		protected override void HashCore (byte[] data, int start, int length) 
		{
			if (hash.Handle == IntPtr.Zero)
				Initialize ();

			hash.HashCore (data, start, length);
		}

		protected override byte[] HashFinal () 
		{
			if (hash.Handle == IntPtr.Zero)
				Initialize ();

			return hash.HashFinal ();
		}
	}
}
";

	static string footer = @"

/* DO NOT EDIT *** This file was generated automatically *** DO NOT EDIT */
";

	static string mhash_base_start = @"
using System;
using System.Security.Cryptography;

namespace Crimson.Security.Cryptography {
";

	static void WriteToFile (string filename, string content)
	{
		using (StreamWriter sw = new StreamWriter (filename)) {
			sw.Write (content);
		}
	}

	static private void GenerateMHashAbstractClass (string dir, MHashId id, double fx)
	{
		string algo = id.ToString ().ToUpper ();
		int size = ((int) MHashWrapper.mhash_get_block_size (id) << 3); // bytes to bits

		StringBuilder sb = new StringBuilder (header);
		sb.Append (mhash_base_start);
		sb.AppendFormat ("{0}\tpublic abstract class {1} : HashAlgorithm {{{0}", Environment.NewLine, algo);
		sb.AppendFormat ("{0}\t\tprotected {1} (){0}\t\t{{", Environment.NewLine, algo);
		sb.AppendFormat ("{0}\t\t\t// {1} digest length is {2} bits long", Environment.NewLine, algo, size);
		sb.AppendFormat ("{0}\t\t\tHashSizeValue = {1};{0}\t\t}}{0}", Environment.NewLine, size);
		sb.AppendFormat ("{0}\t\tpublic static new {1} Create (){0}\t\t{{", Environment.NewLine, algo);
		sb.AppendFormat ("{0}\t\t\treturn Create (\"{1}\");{0}\t\t}}{0}", Environment.NewLine, algo);
		sb.AppendFormat ("{0}\t\tpublic static new {1} Create (string hashName){0}\t\t{{{0}", Environment.NewLine, algo);
		sb.Append ("\t\t\tobject o = CryptoConfig.CreateFromName (hashName);");
		sb.AppendFormat ("{0}\t\t\t// in case machine.config isn't configured to use any {1} implementation", Environment.NewLine, algo);
		sb.AppendFormat ("{0}\t\t\tif (o == null) {{{0}\t\t\t\to = new {1}Native ();{0}\t\t\t}}", Environment.NewLine, algo);
		sb.AppendFormat ("{0}\t\t\treturn ({1}) o;{0}\t\t}}{0}\t}}{0}}}", Environment.NewLine, algo);
		sb.Append (footer);

		string filename = Path.Combine (dir, algo + ".cs");
		WriteToFile (filename, sb.ToString ());
	}

	static private void GenerateMHashClass (string dir, MHashId id, double fx)
	{
		string algo = id.ToString ().ToUpper ();
		string classname = String.Format ("{0}Native", algo);
		string baseclass = " : " + algo;

		StringBuilder sb = new StringBuilder (header);
		sb.Append (mhash_start);
//		if (fx < 2.0){
			sb.AppendFormat ("{0}\tpublic class {1}{2} {{{0}", Environment.NewLine, classname, baseclass);
//		} else {
//			sb.AppendFormat ("{0}#if NET_2_0{0}\tpublic class {1}{2} {{{0}#else{0}\tpublic class {1}{2 : HashAlgorithm {{{0}#endif{0}", 
//				Environment.NewLine, classname, baseclass);
//		}
		sb.AppendFormat ("{0}\t\tprivate MHashId Id = MHashId.{1};{0}", Environment.NewLine, id);
		sb.Append ("\t\tprivate MHashHelper hash;");
		sb.AppendFormat ("{0}{0}\t\tpublic {1} ()", Environment.NewLine, classname);
		sb.Append (mhash_ctor);
		sb.AppendFormat ("\t\t~{0} ()", classname);
		sb.Append (mhash_end);
		sb.Append (footer);

		string filename = Path.Combine (dir, classname + ".cs");
		WriteToFile (filename, sb.ToString ());
	}

	static private void GenerateMHash (string dir, MHashId id)
	{
		string algo = id.ToString ().ToUpper ();
		double fx = 1.0;

		switch (algo) {
		case "SHA1":
		case "MD5":
		case "SHA256":
		case "SHA384":
		case "SHA512":
			// base class already defined in Fx 1.0
			break;
		case "RIPEMD160":
			// base class already defined, but only in Fx 2.0
			GenerateMHashAbstractClass (dir, id, 2.0);
			break;
		default:
			// we need to generate our own base class
			GenerateMHashAbstractClass (dir, id, 1.0);
			break;
		}

		GenerateMHashClass (dir, id, fx);
	}

	static void MHash (string dir)
	{
		Console.WriteLine ("Generating HashAlgorithm for MHash inside directory {0}", dir);
		foreach (MHashId id in Enum.GetValues (typeof (MHashId))) {
			Console.WriteLine ("\t{0}", id);
			GenerateMHash (dir, id);
		}
	}


	static void Main (string[] args)
	{
		string dir = args.Length == 0 ? "." : args [0];
		MHash (dir);
	}
}
