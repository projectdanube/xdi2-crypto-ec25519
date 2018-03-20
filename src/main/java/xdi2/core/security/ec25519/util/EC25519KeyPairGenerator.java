package xdi2.core.security.ec25519.util;
import xdi2.core.security.ec25519.crypto.EC25519Provider;

public class EC25519KeyPairGenerator {

	public static void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws Exception {

		EC25519Provider.get().generateEC25519KeyPair(publicKey, privateKey);
	}

	public static void generateEC25519KeyPairFromSeed(byte[] publicKey, byte[] privateKey, byte[] seed) throws Exception {

		EC25519Provider.get().generateEC25519KeyPairFromSeed(publicKey, privateKey, seed);
	}
}
