using NUnit.Framework;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Crimson.Test.Base {

	public class SymmetricAlgorithmTest {
	
		protected SymmetricAlgorithm algo;

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void CreateEncryptor_KeyNull ()
		{
			ICryptoTransform encryptor = algo.CreateEncryptor (null, algo.IV);
			byte[] data = new byte[encryptor.InputBlockSize];
			byte[] encdata = encryptor.TransformFinalBlock (data, 0, data.Length);

			ICryptoTransform decryptor = algo.CreateDecryptor (algo.Key, algo.IV);
			decryptor.TransformFinalBlock (encdata, 0, encdata.Length);
			// null key != SymmetricAlgorithm.Key
		}

		[Test]
		public void CreateEncryptor_IvNull ()
		{
			ICryptoTransform encryptor = algo.CreateEncryptor (algo.Key, null);
			byte[] data = new byte[encryptor.InputBlockSize];
			byte[] encdata = encryptor.TransformFinalBlock (data, 0, data.Length);

			ICryptoTransform decryptor = algo.CreateDecryptor (algo.Key, algo.IV);
			byte[] decdata = decryptor.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.IsFalse (BitConverter.ToString (data) == BitConverter.ToString (decdata), "Compare");
			// null iv != SymmetricAlgorithm.IV
		}

		[Test]
		public void CreateEncryptor_KeyIv ()
		{
			byte[] originalKey = algo.Key;
			byte[] originalIV = algo.IV;

			byte[] key = (byte[]) algo.Key.Clone ();
			Array.Reverse (key);
			byte[] iv = (byte[]) algo.IV.Clone ();
			Array.Reverse (iv);

			Assert.IsNotNull (algo.CreateEncryptor (key, iv), "CreateEncryptor");

			Assert.AreEqual (originalKey, algo.Key, "Key");
			Assert.AreEqual (originalIV, algo.IV, "IV");
			// SymmetricAlgorithm Key and IV not changed by CreateEncryptor
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		[Category ("NotWorking")] // data is bad but no exception is thrown
		public void CreateDecryptor_KeyNull ()
		{
			ICryptoTransform encryptor = algo.CreateEncryptor (algo.Key, algo.IV);
			byte[] data = new byte[encryptor.InputBlockSize];
			byte[] encdata = encryptor.TransformFinalBlock (data, 0, data.Length);

			ICryptoTransform decryptor = algo.CreateDecryptor (null, algo.IV);
			decryptor.TransformFinalBlock (encdata, 0, encdata.Length);
			// null key != SymmetricAlgorithm.Key
		}

		[Test]
		public void CreateDecryptor_IvNull ()
		{
			ICryptoTransform encryptor = algo.CreateEncryptor (algo.Key, algo.IV);
			byte[] data = new byte[encryptor.InputBlockSize];
			byte[] encdata = encryptor.TransformFinalBlock (data, 0, data.Length);

			ICryptoTransform decryptor = algo.CreateDecryptor (algo.Key, null);
			byte[] decdata = decryptor.TransformFinalBlock (encdata, 0, encdata.Length);
			Assert.IsFalse (BitConverter.ToString (data) == BitConverter.ToString (decdata), "Compare");
			// null iv != SymmetricAlgorithm.IV
		}

		[Test]
		public void CreateDecryptor_KeyIv ()
		{
			byte[] originalKey = algo.Key;
			byte[] originalIV = algo.IV;

			byte[] key = (byte[]) algo.Key.Clone ();
			Array.Reverse (key);
			byte[] iv = (byte[]) algo.IV.Clone ();
			Array.Reverse (iv);

			Assert.IsNotNull (algo.CreateEncryptor (key, iv), "CreateDecryptor");

			Assert.AreEqual (originalKey, algo.Key, "Key");
			Assert.AreEqual (originalIV, algo.IV, "IV");
			// SymmetricAlgorithm Key and IV not changed by CreateDecryptor
		}

		// Setting the IV is more restrictive than supplying an IV to
		// CreateEncryptor and CreateDecryptor. See bug #76483

		private ICryptoTransform CreateEncryptor_IV (int size)
		{
			byte[] iv = (size == -1) ? null : new byte[size];
			return algo.CreateEncryptor (algo.Key, iv);
		}

		[Test]
		public void CreateEncryptor_IV_Null ()
		{
			CreateEncryptor_IV (-1);
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void CreateEncryptor_IV_Zero ()
		{
			CreateEncryptor_IV (0);
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void CreateEncryptor_IV_TooSmall ()
		{
			int size = (algo.BlockSize >> 3) - 1;
			CreateEncryptor_IV (size);
		}

		[Test]
		public void CreateEncryptor_IV_BlockSize ()
		{
			int size = (algo.BlockSize >> 3);
			CreateEncryptor_IV (size);
		}
#if false
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		// Rijndael is the only implementation that has
		// this behaviour for IV that are too large
		[Category ("NotWorking")]
		public void CreateEncryptor_IV_TooBig ()
		{
			int size = algo.BlockSize; // 8 times too big
			CreateEncryptor_IV (size);
		}
#endif
		private ICryptoTransform CreateDecryptor_IV (int size)
		{
			byte[] iv = (size == -1) ? null : new byte[size];
			return algo.CreateDecryptor (algo.Key, iv);
		}

		[Test]
		public void CreateDecryptor_IV_Null ()
		{
			CreateDecryptor_IV (-1);
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void CreateDecryptor_IV_Zero ()
		{
			CreateDecryptor_IV (0);
		}

		[Test]
		[ExpectedException (typeof (CryptographicException))]
		public void CreateDecryptor_IV_TooSmall ()
		{
			int size = (algo.BlockSize >> 3) - 1;
			CreateDecryptor_IV (size);
		}

		[Test]
		public void CreateDecryptor_IV_BlockSize ()
		{
			int size = (algo.BlockSize >> 3);
			CreateDecryptor_IV (size);
		}
#if false
		[Test]
		[ExpectedException (typeof (CryptographicException))]
		// Rijndael is the only implementation that has
		// this behaviour for IV that are too large
		[Category ("NotWorking")]
		public void CreateDecryptor_IV_TooBig ()
		{
			int size = algo.BlockSize; // 8 times too big
			CreateDecryptor_IV (size);
		}
#endif
	}
}
