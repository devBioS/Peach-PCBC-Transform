using System;
using System.Collections.Generic;
//using System.Security.Authentication;
//using System.Text;
//using System.IO.Compression;
using System.IO;
//using System.Security.Cryptography;
//using Peach.Core.Dom;
using Peach.Core.IO;
using OpenSSL.Crypto;

namespace Peach.Core.Transformers.Crypto
{
	[Description("DES_PCBC transform (hex & binary).")]
	[Transformer("DES_PCBC", true)]
	[Transformer("crypto.DES_PCBC")]
	[Parameter("Key", typeof(HexString), "Secret Key")]
	[Parameter("IV", typeof(HexString), "Initialization Vector")]
	[Serializable]
	public class DES_PCBC : Transformer
	{
		public HexString Key { get; protected set; }
        public HexString IV { get; protected set; }

		public DES_PCBC(Dictionary<string, Variant> args)
		           : base(args)
		{
			ParameterParser.Parse(this, args);
		}

		protected override BitwiseStream internalEncode(BitwiseStream data)
		{
			byte[] input;
			using (var streamReader = new MemoryStream())
            {
                data.CopyTo(streamReader);
                input = streamReader.ToArray();
            }
			byte[] result = Encrypt_DES_PCBC(input, Key.Value, IV.Value);
			
			return new BitStream(result);
		}

		protected override BitStream internalDecode(BitStream data)
		{
			byte[] input;
			using (var streamReader = new MemoryStream())
            {
                data.CopyTo(streamReader);
                input = streamReader.ToArray();
            }
			byte[] result = Decrypt_DES_PCBC(input, Key.Value, IV.Value);
			return new BitStream(result);
		}
		
		private byte[] Encrypt_DES_PCBC(byte[] inputMsg, byte[] keyin, byte[] ivin) {
			byte[] key = new byte[keyin.Length];
			keyin.CopyTo(key,0);
			byte[] iv = new byte[ivin.Length];
			ivin.CopyTo(iv,0);
			
			//Add 0x00 padding to provide an input multiple to 8
			int inputPadding = 8 - (inputMsg.Length % 8);
			byte[] input = new byte[inputMsg.Length + inputPadding];

			inputMsg.CopyTo(input,0);

			byte[] encryptedmessage = new byte[input.Length];
			
			Cipher cipher = Cipher.DES_CBC;
			using (var cc = new CipherContext(cipher))
			{
				byte[] lastEncrypt = new byte[8];
				byte[] lastPlaintext = new byte[8];
				for (int i = 0; i < input.Length; i+=8) {
					byte[] plaintext = new byte[8];
					byte[] encrypted = new byte[8];
					
					System.Array.Copy(input, i, plaintext, 0, 8);
					if (i > 0) {
						for(int z = 0; z < iv.Length; z++)
						{
							iv[z] = (byte) (lastEncrypt[z] ^ lastPlaintext[z]);
						}
					}
					byte[] encryptedtmp = cc.Encrypt(plaintext, key, iv); 
					System.Array.Copy(encryptedtmp, 0, encrypted, 0, 8);
					lastEncrypt = encrypted;
					lastPlaintext = plaintext;
					for (int f = 0; f < 8;f++) {
						encryptedmessage[f+i] = encrypted[f];
					}
				}
			}
			
			return encryptedmessage;
		}
		
		private byte[] Decrypt_DES_PCBC(byte[] encryptedMsg, byte[] keyin, byte[] ivin) {
			Cipher cipher = Cipher.DES_CBC;

			byte[] key = new byte[keyin.Length];
			keyin.CopyTo(key,0);
			byte[] iv = new byte[ivin.Length];
			ivin.CopyTo(iv,0);			
			
			byte[] decryptedmessage = new byte[encryptedMsg.Length];
			
			using (var cc = new CipherContext(cipher))
			{
				byte[] lastEncrypted = new byte[16];
				byte[] lastPlaintext = new byte[8];
				for (int i = 0; i < encryptedMsg.Length; i+=8) {
					byte[] encrypted = new byte[16];

					System.Array.Copy(encryptedMsg, i, encrypted, 0, 8);
					encrypted[8] = 0x20;
					if (i > 0) {
						for(int z = 0; z < iv.Length; z++)
						{
							iv[z] = (byte) (lastEncrypted[z] ^ lastPlaintext[z]);
						}
					}
					byte[] decrypted = cc.Decrypt(encrypted, key, iv);
					lastEncrypted = encrypted;
					lastPlaintext = decrypted;

					for (int f = 0; f < 8;f++) {
						decryptedmessage[f+i] = decrypted[f];
					}
				}			
			}
			return decryptedmessage;
		}

	}
}