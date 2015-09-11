package com.github.dazoe.android;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/*
 * From https://github.com/dazoe/Android.Ed25519.git
 */
public class Ed25519 {
	private native static byte[] ExpandPrivateKeyN(byte[] privateKey);
	private native static byte[] SignN(byte[] message, byte[] privateKey);
	private native static int VerifyN(byte[] message, byte[] signature, byte[] publicKey);

	public static byte[] ExpandPrivateKey(byte[] privateKey) throws Exception {
		if ((privateKey.length != 32) && (privateKey.length != 64)) throw new Exception("Invalid privateKey length, 32 bytes please");
		if (privateKey.length == 64) { //already expanded.
			return privateKey;
		}
		return ExpandPrivateKeyN(privateKey); 
	}
	public static byte[] PublicKeyFromPrivateKey(byte[] privateKey) throws Exception {
		if ((privateKey.length != 32) && (privateKey.length != 64)) throw new Exception("Invalid privateKey length, 32 or 64 bytes please");
		if (privateKey.length == 32) {
			privateKey = ExpandPrivateKey(privateKey);
		}
		return Arrays.copyOfRange(privateKey, 32, 64);
	}
	public static byte[] Sign(byte[] message, byte[] privateKey) throws Exception {
		if ((privateKey.length != 32) && (privateKey.length != 64)) throw new Exception("Invalid privateKey length, must be 32 or 64 bytes");
		if (privateKey.length == 32) {
			privateKey = ExpandPrivateKey(privateKey);
		}
		return SignN(message, privateKey);
	}
	public static int Verify(byte[] message, byte[] signature, byte[] publicKey) throws Exception {
		if (publicKey.length != 32) throw new Exception("Invalid publicKey length, must be 32 bytes");
		if (signature.length != 64) return -1;
		return VerifyN(message, signature, publicKey);
	}
	
	//Um, yeah, this was the best I could do with my current JNI skill level
	// jni c code calls this for sha512.
	private static MessageDigest SHA512_Init() {
		try {
			return MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	private static void SHA512_Update(MessageDigest md, byte[] data) {
		md.update(data);
	}
	private static byte[] SHA512_Final(MessageDigest md) {
		return md.digest();
	}
	static {
		System.loadLibrary("ed25519_android");
	}
}
