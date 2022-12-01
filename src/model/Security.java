package model;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Security {

	// CONSTNATES A USAR
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

	private static final String SIG = "SHA1WithRSA";

	private static final String KEY_ALGORITHM = "RSA";

	private static final int KEY_SIZE = 1024;

	private static final String PRIVATE_KEY_FILE = "privateKey";

	private static final String PUBLIC_KEY_FILE = "publicKey";

	// PRIMER PUNTO
	public void keyGenerator(String password) {

		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGenerator.initialize(KEY_SIZE);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();

			PublicKey publicKey = keyPair.getPublic();
			savePublicKey(publicKey);
			
			PrivateKey privateKey = keyPair.getPrivate();
			savePrivateKey(privateKey);

			FileWriter outFile = null;
			PrintWriter pw = null;

			try {

				String pkCIF = encript(PRIVATE_KEY_FILE + ".key", password);

				outFile = new FileWriter(PRIVATE_KEY_FILE + ".cif");
				pw = new PrintWriter(outFile);

				pw.println(pkCIF);

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} finally {
				try {
					if (outFile != null) {
						outFile.close();
						pw.close();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			}

			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

	}

	public void savePrivateKey(PrivateKey key) {

		Base64.Encoder encoder = Base64.getEncoder();
		FileWriter outFile = null;
		PrintWriter pw = null;

		try {
			outFile = new FileWriter(PRIVATE_KEY_FILE + ".key");
			pw = new PrintWriter(outFile);
			
			String inputString = encoder.encodeToString(key.getEncoded()).replaceAll("[\n|\r|\t|=]", "");
			byte[] data = inputString.getBytes("UTF8");
			
			pw.println(encoder.encodeToString(data));

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

	public static String encript(String inputFile, String password) throws Exception {
		Key aesKey = new SecretKeySpec(password.getBytes(), "AES");

		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey);

		byte[] encrypted = cipher.doFinal(inputFile.getBytes());

		return Base64.getEncoder().encodeToString(encrypted);
	}

	public static String decrypt(File encryptedFile, String password)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		FileReader fr;
		BufferedReader br;
		String privateKey = null;
		try {
			fr = new FileReader(encryptedFile);
			
			br = new BufferedReader(fr);
			
			privateKey = br.readLine();
		} catch ( IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		byte[] encryptedBytes = Base64.getDecoder().decode(privateKey.replace("\n", ""));

		Key aesKey = new SecretKeySpec(password.getBytes(), "AES");
		

		Cipher cipher = Cipher.getInstance("AES");
		try {
			cipher.init(Cipher.DECRYPT_MODE, aesKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

		String decrypted = new String(cipher.doFinal(encryptedBytes));

		return decrypted;
	}

	public void savePublicKey(PublicKey key) {

		Base64.Encoder encoder = Base64.getEncoder();
		FileWriter outFile = null;
		PrintWriter pw = null;

		try {
			outFile = new FileWriter(PUBLIC_KEY_FILE + ".key");
			pw = new PrintWriter(outFile);

			pw.println(encoder.encodeToString(key.getEncoded()));

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

	// AYUDA
	public static IvParameterSpec generateIv() {

		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static void encryptFileWithKeys(SecretKey key, File inputFile, File outputFile)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		// AYUDA
		IvParameterSpec iv = generateIv();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outputFile);
		// byte[] hash = hash(inputFile);
		// fos.write(hash);
		byte[] ivB = iv.getIV();
		fos.write(ivB);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = fis.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				fos.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			fos.write(outputBytes);
		}
		fis.close();
		fos.close();
	}

	///////////////////////////////////////////////

	// VERIFICAR EL DOCUMENTO FIRMADO
	@SuppressWarnings("unused")
	private static boolean verifyFileSigner(String fileToCheck, String fileSig) throws NoSuchAlgorithmException,
			InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {

		PublicKey pk = readPublicKey(new File("../publicKey"));
		Signature signatu = Signature.getInstance("SHA1withRSA");
		signatu.initVerify(pk);

		FileInputStream fis = new FileInputStream(fileSig);
		byte[] sigFile = new byte[fis.available()];
		fis.read(sigFile);
		fis.close();

		FileInputStream fisTwo = new FileInputStream(fileToCheck);
		BufferedInputStream bis = new BufferedInputStream(fisTwo);
		byte[] buffer = new byte[1024];

		int len;
		while (bis.available() != 0) {
			len = bis.read(buffer);
			signatu.update(buffer, 0, len);
		}
		;

		bis.close();

		return signatu.verify(sigFile);
	}

	// LEER LAS LLAVES PARA VERIFICAR EL DOCUMENTO FIRMADO

	// Leer llave pública
	private static PublicKey readPublicKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] output = null;

		try (FileInputStream fis = new FileInputStream(file)) {
			output = fis.readAllBytes();

		} catch (IOException e) {
			e.printStackTrace();
		}

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(output);

		return keyFactory.generatePublic(keySpec);
	}

	// Leer llave privada
	public static PrivateKey readPrivateKey(byte[] input) throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input);
		return keyFactory.generatePrivate(keySpec);
	}

	// FIRMAR EL DOCUMENTO
	//@SuppressWarnings("unused")
	public static void signFile(String fileToSign, PrivateKey pk)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {

		Signature signatu = Signature.getInstance(SIG);
		signatu.initSign(pk);

		FileInputStream fis = new FileInputStream(fileToSign);
		BufferedInputStream bis = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];

		int len;
		while ((len = bis.read(buffer)) >= 0) {
			signatu.update(buffer, 0, len);
		}
		;
		bis.close();

		byte[] realSig = signatu.sign();

		FileOutputStream fos = new FileOutputStream(fileToSign + ".sig");
		fos.write(realSig);
		fos.close();
	}

	// Se desencripta y se conprueba la llave privada con la contraseña para firmar
	// el doc.
	public static byte[] verifyPass(SecretKey key, File inputFile)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		byte[] output = null;

		try (FileInputStream fis = new FileInputStream(inputFile)) {

			byte[] hash = new byte[20];
			fis.read(hash);
			byte[] ivB = new byte[16];
			fis.read(ivB);

			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivB));

			output = cipher.doFinal(fis.readAllBytes());
			// byte[] expectedHash = hash(output);

//			for (int i = 0; i < expectedHash.length; i++) {
//				if(hash[i] != expectedHash[i]) {
//					return null;
//				}
//			}
			return output;

		} catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public PrivateKey stringToPrivateK(String pvk) {
		
		byte[] privateBytes = Base64.getDecoder().decode(pvk.replaceAll("=", ""));
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(privateBytes);
		KeyFactory keyFactory;
		
		PrivateKey privKey = null;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			privKey = keyFactory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return privKey;
	}
	
	public PublicKey stringToPublicK(String publicKeyPath) {
		
		File pbKFile = new File(publicKeyPath);
		FileReader fr = null;
		BufferedReader br = null;
		String publicKeyString = null;
		try {
			fr = new FileReader(pbKFile);
			br = new BufferedReader(fr);
			
			publicKeyString = br.readLine();
			
			fr.close();
			br.close();
			
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		KeyFactory keyFactory;
		
		PublicKey publicKey = null;
		
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return publicKey;
	}

}// end
