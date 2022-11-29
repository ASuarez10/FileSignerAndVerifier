package model;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

public class Security {
	
	
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
			
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
	
	//AYUDA
	public static IvParameterSpec generateIv() {

		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}
	
	public static void encryptFile(SecretKey key, File inputFile, File outputFile) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, 
	InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		//AYUDA
		IvParameterSpec iv = generateIv();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		FileInputStream inputStream = new FileInputStream(inputFile);
		FileOutputStream outputStream = new FileOutputStream(outputFile);
		byte[] hash = hash(inputFile);
		outputStream.write(hash);
		byte[] ivB = iv.getIV();
		outputStream.write(ivB);
		byte[] buffer = new byte[64];
		int bytesRead;
		while ((bytesRead = inputStream.read(buffer)) != -1) {
			byte[] output = cipher.update(buffer, 0, bytesRead);
			if (output != null) {
				outputStream.write(output);
			}
		}
		byte[] outputBytes = cipher.doFinal();
		if (outputBytes != null) {
			outputStream.write(outputBytes);
		}
		inputStream.close();
		outputStream.close();
	}
	
	

	//VERIFICAR EL DOCUMENTO FIRMADO
	private static boolean verifyFile(String fileToCheck, String fileSig) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException, IOException {
		boolean res =false;
			PublicKey pk = readPublicKey(new File(PUBLIC_KEY_FILE));
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(pk);
			
			FileInputStream sigfis = new FileInputStream(fileSig);
			byte[] sigFile = new byte[sigfis.available()];
			sigfis.read(sigFile);
			sigfis.close();
			
			FileInputStream datafis = new FileInputStream(fileToCheck);
			BufferedInputStream bufin = new BufferedInputStream(datafis);
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
			    len = bufin.read(buffer);
			    sig.update(buffer, 0, len);
			};
			bufin.close();
			
		return sig.verify(sigFile);
	}
	
	//LEER LAS LLAVES PARA VERIFICAR EL DOCUMENTO FIRMADO
	
	//Leer llave pública
	private static PublicKey readPublicKey(File file) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] output = null;
		try(FileInputStream fis = new FileInputStream(file)){
		   output=fis.readAllBytes();
		} catch (IOException e){
		    e.printStackTrace();
		}
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(output);
		return keyFactory.generatePublic(keySpec);
	}
	     
	//Leer llave privada
	public static PrivateKey readPrivateKey(byte[] input) throws Exception {

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(input);
		return keyFactory.generatePrivate(keySpec);
	}
	
	//FIRMAR EL DOCUMENTO
	private static void signFile(String fileToSign, PrivateKey pk) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IOException {
		Signature sig = Signature.getInstance("SHA1WithRSA");
		sig.initSign(pk);
		FileInputStream fis = new FileInputStream(fileToSign);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
		    sig.update(buffer, 0, len);
		};
		bufin.close();
		
		byte[] realSig = sig.sign();
		
		FileOutputStream sigfos = new FileOutputStream(fileToSign+".sig");
		sigfos.write(realSig);
		sigfos.close();
	}
	
	//Comprobación de la clave de la llave privada para firmar el doc
	public static byte[] decrypt(SecretKey key, File inputFile) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		byte[] output = null;
		try (FileInputStream inputStream = new FileInputStream(inputFile)) {
			byte[] hash = new byte[20];
			inputStream.read(hash);
			byte[] ivB = new byte[16];
			inputStream.read(ivB);

			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivB));

			output = cipher.doFinal(inputStream.readAllBytes());
			byte[] expectedHash = hash(output);
			for (int i = 0; i < expectedHash.length; i++) {
				if(hash[i] != expectedHash[i]) {
					return null;
				}
			}
			return output;
		} catch (IOException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			return null;
		}
}// end
