package ui;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import model.Security;

public class Main {
	
	private static final String PRIVATE_KEY_FILE = "privateKey";
	private static final String PUBLIC_KEY_FILE = "publicKey";

	public static void main(String[] args) {

		try {
			menu();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public static void menu() throws Exception {

		Security logic = new Security();

		Scanner ansNum = new Scanner(System.in);
		Scanner ansPass = new Scanner(System.in);

		String pass;
		System.out.println("BIENVENIDO: ");
		System.out.println("-------------------OPCIONES-------------------");
		System.out.println("[1] Generar llave pública y privada.");
		System.out.println("[2] Firmar documento.");
		System.out.println("[3] Verificar firma del documento.");

		int answer = ansNum.nextInt();
		
		switch (answer) {
		
		case 1:

			System.out.println("Digite la contraseña para la llave privada (Debe tener 16 caracteres):");
			pass = ansPass.nextLine();
			logic.keyGenerator(pass);
			System.out.println("Las nuevas llaves han sido creadas exitosamente.");
			menu();
			
		case 2:
			
			System.out.println("Digite el nombre del archivo de la clave privada. (Ejemplo: privateKey.cif)");
			String privateKeyPath = ansPass.nextLine();
			
			
			//File inputFile = new File(PRIVATE_KEY_FILE + ".cif");
			File inputFile = new File(privateKeyPath);
			System.out.print("Digite la contraseña para desencriptar la clave privada: ");
			String password = ansPass.nextLine();

			try {
				// byte[] output = decrypt(getKeyFromPassword(pass), inputFile);
				String output = logic.decrypt(inputFile, password);
				
				if (output != null) {

					System.out.println("Llave privada desencriptada existosamente");

					PrivateKey pk = logic.stringToPrivateK(output);
					System.out.print("- Digite el nombre del archivo para firmar: ");
					String fileToSign = ansPass.nextLine();

					if (new File(fileToSign).exists()) {
						logic.signFile(fileToSign, pk);
						System.out.println("Archivo firmado.");
					}else {
						System.out.println("Archivo '" + fileToSign + "' NO existe.");
					}
				} else {
					System.out.println("La contraseña es incorrecta.");
					menu();
				}
			} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
					| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
					| InvalidKeySpecException | IOException e) {
				e.printStackTrace();
			}
			menu();

//		case 3:
//			System.out.println("- Digite el nombre del archivo que desea revisar");
//			String fileToCheck = ansPass.nextLine();
//
//			String fileSigner = fileToCheck + ".sig";
//
//			try {
//				if (logic.verifyFileSigner(fileToCheck, fileSigner)) {
//					System.out.println("-------------> La firma ha sido verificada <-------------");
//				} else {
//					System.out.println("-------------> Las llaves no coinciden <-------------");
//				}
//			} catch (IOException e) {
//				e.printStackTrace();
//			}
//
//			break;
		default:
			break;

		}
		ansPass.close();
	}

}
