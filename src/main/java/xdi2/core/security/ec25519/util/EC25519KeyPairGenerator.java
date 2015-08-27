package xdi2.core.security.ec25519.util;
import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

public class EC25519KeyPairGenerator {

	public static void generateEC25519KeyPair(byte[] publicKey, byte[] privateKey) throws Exception {

		NaCl.init();
		Sodium sodium = NaCl.sodium();

		// create seed

		byte[] seed = new byte[256];

		sodium.randombytes(seed, 256);
		seed = SHA256.sha256(seed);

		// create key pairs

		sodium.crypto_sign_ed25519_seed_keypair(publicKey, privateKey, seed);
	}
}
