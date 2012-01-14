using System;

using Crimson.Security.Cryptography;
using Crimson.Test.Base;

using NUnit.Framework;

namespace Crimson.Test.Generated.MHash {
	
	[TestFixture]
	public class SHA1NativeTest : SHA1Test {
		
		[SetUp]
		protected void SetUp () 
		{
			hash = new SHA1Native ();
		}
	}
}
