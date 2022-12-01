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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Security {

	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

	private static final String SIG = "SHA1withRSA";

	private static final String KEY_ALGORITHM = "RSA";

	private static final int KEY_SIZE = 1024;

	private static final String PRIVATE_KEY_FILE = "privateKey";

	private static final String PUBLIC_KEY_FILE = "publicKey";

	private static final String MSG_DIGEST = "SHA-1";

	private static final String SALT = "SEGURIDAD";

	private static final String SECRET_KEY_ALGORITHM = "AES";

	private static final String AUTH_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";

	// PRIMER PUNTO

	public void keyGenerator(char[] pass) throws Exception {
		KeyPairGenerator keyPairGenerator = null;

		try {
			keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGenerator.initialize(KEY_SIZE);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			Key publicKey = keyPair.getPublic();
			Key privateKey = keyPair.getPrivate();
			saveKey(publicKey, PUBLIC_KEY_FILE + ".key");
			saveKey(privateKey, PRIVATE_KEY_FILE + ".key");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		File inputFile = new File(PRIVATE_KEY_FILE + ".key");
		try {
			encryptFileWithKeys(getKeyFromPassword(pass), inputFile, new File(PRIVATE_KEY_FILE + ".cif"));
			inputFile.delete();
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| InvalidKeySpecException | IOException e) {
			e.printStackTrace();
		}
	}

	public void saveKey(Key key, String fileName) {
		try (FileOutputStream out = new FileOutputStream(fileName)) {
			out.write(key.getEncoded());
			out.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// Generamos el vector de inicializacion para la primera iteracion del proceso
	// de encriptado
	public IvParameterSpec generateIv() {

		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	// Encripta el archivo de entrada con la contraseña
	public void encryptFileWithKeys(SecretKey key, File inputFile, File outputFile)
			throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		// AYUDA
		IvParameterSpec iv = generateIv();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream fis = new FileInputStream(inputFile);
		FileOutputStream fos = new FileOutputStream(outputFile);
		byte[] hash = hashEncrypt(inputFile);
		fos.write(hash);
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

	// SEGUNDO PUNTO/////////////////////////////////

	// Se leen los bytes de la llave privada y se convierten a un objeto PrivateKey.
	public PrivateKey convertToPvKey(byte[] input) throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input);
		return keyFactory.generatePrivate(keySpec);
	}

	// Se firma el documento de entrada con la llave privada y la funcion hash SHA1
	public void signFile(String fileToSign, PrivateKey pk)
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

	// Lee la contraseña ingresada por el usuario y con esto genera una SecretKey
	// anadiendole la sal.
	public SecretKey getKeyFromPassword(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Calcula un codigo de autenticacion con la funcion hash SHA256 y la funcion
		// matematica de derivacion de claves PBKDF2
		SecretKeyFactory factory = SecretKeyFactory.getInstance(AUTH_KEY_ALGORITHM);
		KeySpec spec = new PBEKeySpec(password, SALT.getBytes(), 65536, 128);
		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), SECRET_KEY_ALGORITHM);
		return secret;
	}

	// Se desencripta y se conprueba la llave privada con la contraseña para firmar
	// el doc.
	public byte[] verifyPass(SecretKey key, File inputFile)
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
			byte[] expectedHash = hashExpected(output);

			for (int i = 0; i < expectedHash.length; i++) {
				if (hash[i] != expectedHash[i]) {
					return null;
				}
			}
			return output;

		} catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException e) {
			e.printStackTrace();
			System.out.println("Contraseña incorrecta");
			return null;
		}
	}

	// Se usa un message digest verificar que el archivo no ha sido modificado.
	public byte[] hashExpected(byte[] input) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(MSG_DIGEST);
		digest.update(input);
		return digest.digest();
	}

	// Se usa para autenticar el archivo y para más adelante verificar su no
	// modificacion.
	public byte[] hashEncrypt(File file) throws IOException, NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance(MSG_DIGEST);
		try (FileInputStream fis = new FileInputStream(file)) {
			byte[] buffer = new byte[8192];
			int bytesRead;
			while ((bytesRead = fis.read(buffer)) != -1) {
				if (bytesRead > 0)
					digest.update(buffer, 0, bytesRead);
			}
			return digest.digest();
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	/////////////////////////////////////////////////////////////////////////////////// 7
	// TERCER
	/////////////////////////////////////////////////////////////////////////////////// PUNTO//////////////////////////////////////////////////////////////////////

	// Se verifica la firma del documento de entrada con la funcion hash SHA1
	public boolean verifyFileSigned(String fileToCheck, String fileSig, File pbk) throws NoSuchAlgorithmException,
			InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {

		PublicKey pk = convertToPbKey(pbk);
		Signature signatu = Signature.getInstance(SIG);
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
		bis.close();
		return signatu.verify(sigFile);
	}

	// LEER LAS LLAVES PARA VERIFICAR EL DOCUMENTO FIRMADO

	// Leer el arichivo de la clave public y lo convierte a un objeto PublicKey.
	private PublicKey convertToPbKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException {
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

	/////////////////////////////////////////////////////////////////////////////////

//Métodos no usados

//	public void savePrivateKey(PrivateKey key) {
	//
//				Base64.Encoder encoder = Base64.getEncoder();
//				FileWriter outFile = null;
//				PrintWriter pw = null;
	//
//				try {
//					outFile = new FileWriter(PRIVATE_KEY_FILE + ".key");
//					pw = new PrintWriter(outFile);
//					
//					String inputString = encoder.encodeToString(key.getEncoded()).replaceAll("[\n|\r|\t|=]", "");
//					byte[] data = inputString.getBytes("UTF8");
//					
//					pw.println(encoder.encodeToString(data));
	//
//				} catch (Exception e) {
//					e.printStackTrace();
//				} finally {
//					try {
//						// Nuevamente aprovechamos el finally para
//						// asegurarnos que se cierra el fichero.
//						if (null != outFile) {
//							outFile.close();
//							pw.close();
//						}
//					} catch (Exception e2) {
//						e2.printStackTrace();
//					}
//				}
	//
//			}
	//
	//
	//
//			public void savePublicKey(PublicKey key) {
	//
//				Base64.Encoder encoder = Base64.getEncoder();
//				FileWriter outFile = null;
//				PrintWriter pw = null;
	//
//				try {
//					outFile = new FileWriter(PUBLIC_KEY_FILE + ".key");
//					pw = new PrintWriter(outFile);
	//
//					pw.println(encoder.encodeToString(key.getEncoded()));
	//
//				} catch (Exception e) {
//					e.printStackTrace();
//				} finally {
//					try {
//						// Nuevamente aprovechamos el finally para
//						// asegurarnos que se cierra el fichero.
//						if (null != outFile) {
//							outFile.close();
//							pw.close();
//						}
//					} catch (Exception e2) {
//						e2.printStackTrace();
//					}
//				}
	//
//			}	

//	public String encript(String inputFile, String password) throws Exception {
//	Key aesKey = new SecretKeySpec(password.getBytes(), "AES");
//
//	Cipher cipher = Cipher.getInstance("AES");
//	cipher.init(Cipher.ENCRYPT_MODE, aesKey);
//
//	byte[] encrypted = cipher.doFinal(inputFile.getBytes());
//
//	return Base64.getEncoder().encodeToString(encrypted);
//}
//
//public String decrypt(File encryptedFile, String password)
//		throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
//	
//	FileReader fr;
//	BufferedReader br;
//	String privateKey = null;
//	try {
//		fr = new FileReader(encryptedFile);
//		
//		br = new BufferedReader(fr);
//		
//		privateKey = br.readLine();
//	} catch ( IOException e1) {
//		e1.printStackTrace();
//	}
//	
//	byte[] encryptedBytes = Base64.getDecoder().decode(privateKey.replace("\n", ""));
//
//	Key aesKey = new SecretKeySpec(password.getBytes(), "AES");
//	
//
//	Cipher cipher = Cipher.getInstance("AES");
//	try {
//		cipher.init(Cipher.DECRYPT_MODE, aesKey);
//	} catch (InvalidKeyException e) {
//		e.printStackTrace();
//		return null;
//	}
//
//	String decrypted = new String(cipher.doFinal(encryptedBytes));
//
//	return decrypted;
//}

//	@SuppressWarnings("unused")
//	public PrivateKey stringToPrivateK(String pvk) {
//		
//		byte[] privateBytes = Base64.getDecoder().decode(pvk.replaceAll("=", ""));
//		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(privateBytes);
//		KeyFactory keyFactory;
//		
//		PrivateKey privKey = null;
//		try {
//			keyFactory = KeyFactory.getInstance("RSA");
//			privKey = keyFactory.generatePrivate(keySpec);
//		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
//			e.printStackTrace();
//		}
//		
//		return privKey;
//	}

//	@SuppressWarnings("unused")
//	public PublicKey stringToPublicK(String publicKeyPath) {
//		
//		File pbKFile = new File(publicKeyPath);
//		FileReader fr = null;
//		BufferedReader br = null;
//		String publicKeyString = null;
//		try {
//			fr = new FileReader(pbKFile);
//			br = new BufferedReader(fr);
//			
//			publicKeyString = br.readLine();
//			
//			fr.close();
//			br.close();
//			
//		} catch (IOException e1) {
//			e1.printStackTrace();
//		}
//		
//		byte[] publicBytes = Base64.getDecoder().decode(publicKeyString);
//		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//		KeyFactory keyFactory;
//		
//		PublicKey publicKey = null;
//		
//		try {
//			keyFactory = KeyFactory.getInstance("RSA");
//			publicKey = keyFactory.generatePublic(keySpec);
//		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
//			e.printStackTrace();
//		}
//		
//		return publicKey;
//	}

//	public void keyGenerator(String password) {
//
//		try {
//			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
//			keyPairGenerator.initialize(KEY_SIZE);
//			KeyPair keyPair = keyPairGenerator.generateKeyPair();
//
//			PublicKey publicKey = keyPair.getPublic();
//			savePublicKey(publicKey);
//			
//			PrivateKey privateKey = keyPair.getPrivate();
//			savePrivateKey(privateKey);
//
//			FileWriter outFile = null;
//			PrintWriter pw = null;
//
//			try {
//
//				String pkCIF = encript(PRIVATE_KEY_FILE + ".key", password);
//
//				outFile = new FileWriter(PRIVATE_KEY_FILE + ".cif");
//				pw = new PrintWriter(outFile);
//
//				pw.println(pkCIF);
//
//			} catch (Exception e) {
//				e.printStackTrace();
//			} finally {
//				try {
//					if (outFile != null) {
//						outFile.close();
//						pw.close();
//					}
//				} catch (IOException e) {
//					e.printStackTrace();
//				}
//			}
//
//			
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		}
//
//	}

}// end
