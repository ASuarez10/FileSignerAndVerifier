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

		System.out.println("1. Generar llave pública y privada.");
		System.out.println("2. Firmar documento.");
		System.out.println("3. Verificar firma del documento.");

		Scanner ansNum = new Scanner(System.in);
		Scanner ansPass = new Scanner(System.in);
		int answer = ansNum.nextInt();

		switch (answer) {

		case 1:

			char[] password;
			System.out.println("Digite la contraseña para la llave privada (Debe tener 16 caracteres)");
			password = ansPass.nextLine().toCharArray();
			logic.keyGenerator(password);
			System.out.println("Las nuevas llaves han sido creadas exitosamente.");
			menu();

		case 2:

			System.out.println("Digite el nombre del archivo de la clave privada. (Ejemplo: privateKey.cif)");
			String privateKeyPath = ansPass.nextLine();

			File inputFile = new File(privateKeyPath);
			System.out.print("Digite la contraseña para desencriptar la clave privada");
			char[] password2 = ansPass.nextLine().toCharArray();

			try {
				byte[] output = logic.verifyPass(logic.getKeyFromPassword(password2), inputFile);

				if (output != null) {

					System.out.println("Llave privada desencriptada existosamente.");

					PrivateKey pk = logic.convertToPvKey(output);
					
					System.out.print("Digite el nombre del archivo para firmar. (Por ejemplo: Test.txt).");
					String fileToSign = ansPass.nextLine();

					if (new File(fileToSign).exists()) {
						logic.signFile(fileToSign, pk);
						System.out.println("Archivo firmado.");
					} else {
						System.out.println("Archivo '" + fileToSign + "' NO existe.");
					}
				} else {
					menu();
				}
			} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
					| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
					| InvalidKeySpecException | IOException e) {
				e.printStackTrace();
			}
			menu();

		case 3:
			System.out.println("Digite el nombre del archivo que desea revisar. (Por ejemplo: Test.txt)");
			String fileToCheck = ansPass.nextLine();

			System.out.println("Digite el nombre completo del archivo con la firma. (Por ejemplo: Test.txt.sig)");
			String sign = ansPass.nextLine();

			System.out.println(
					"Digite el nombre completo del archivo con la clave pública. (Por ejemplo: publicKey.key)");
			String publicKeyPath = ansPass.nextLine();

			File pbk = new File(publicKeyPath);

			if (pbk.exists()) {

				try {
					if (logic.verifyFileSigned(fileToCheck, sign, pbk)) {
						System.out.println("La firma ha sido verificada");
						ansPass.close();
						ansNum.close();
					} else {
						System.out.println("Las firma no coincide");
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			} else {
				System.out.println("El archivo de clave publica no existe");
			}

			break;
		default:
			break;

		}
//		ansPass.close();
//		ansNum.close();
	}
	
	

}
