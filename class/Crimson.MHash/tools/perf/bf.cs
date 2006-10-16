using System;
using System.IO;

class Program {

	static void Main (string[] args)
	{
		string filename = (args.Length == 0) ? "bigfile" : args [0];
		long size = (args.Length < 2) ? 10000000 : Int64.Parse (args [1]);
		using (FileStream fs = File.OpenWrite (filename)) {
			byte[] k = new byte [1024];
			while (size >= 1024) {
				fs.Write (k, 0, 1024);
				size -= 1024;
			}
			if (size > 0)
				fs.Write (k, 0, (int)size);
			fs.Close ();
		}
	}
}
