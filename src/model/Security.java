package model;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Security {

	private static final String KEY_ALGORITHM = "RSA";

	private static final int KEY_SIZE = 1024;

	public void keyGenerator() {

		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGenerator.initialize(KEY_SIZE);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			PublicKey publicKey = keyPair.getPublic();
			savePublicKey(publicKey);
			PrivateKey privateKey = keyPair.getPrivate();
			savePrivateKey(privateKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	public void savePrivateKey(PrivateKey key) {

		Base64.Encoder encoder = Base64.getEncoder();
		FileWriter outFile = null;
		PrintWriter pw = null;
		
		try {
			outFile = new FileWriter("privateKey.txt");
			pw = new PrintWriter(outFile);

			pw.println("—-BEGIN RSA PRIVATE KEY—-");
			pw.println("\n");

			pw.println(encoder.encodeToString(key.getEncoded()));
			pw.println("\n");

			pw.println("—-END RSA PRIVATE KEY—-");
			pw.println("\n");

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				// Nuevamente aprovechamos el finally para
				// asegurarnos que se cierra el fichero.
				if (null != outFile) {
					outFile.close();
					pw.close();
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		}

	}
	
	public void savePublicKey(PublicKey key) {

		Base64.Encoder encoder = Base64.getEncoder();
		FileWriter outFile = null;
		PrintWriter pw = null;
		
		
		
		try {
			outFile = new FileWriter("publicKey.txt");
			pw = new PrintWriter(outFile);

			pw.println("—-BEGIN RSA PUBLIC KEY—-");
			pw.println("\n");

			pw.println(encoder.encodeToString(key.getEncoded()));
			pw.println("\n");

			pw.println("—-END RSA PUBLIC KEY—-");
			pw.println("\n");

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				// Nuevamente aprovechamos el finally para
				// asegurarnos que se cierra el fichero.
				if (null != outFile) {
					outFile.close();
					pw.close();
				}
			} catch (Exception e2) {
				e2.printStackTrace();
			}
		}

	}
}// end
