package ui;

import model.Security;

public class Main {

	public static void main(String[] args) {
		
		Security logic = new Security();
		menu();

	}
	public static void menu() throws Exception {
		char[] pass;
		System.out.println("BIENVENIDO: ");
		System.out.println("-------------------OPCIONES-------------------");
		System.out.println("[1] Generar llave pública y privada.");
		System.out.println("[2] Firmar documento.");
		System.out.println("[3] Verificar firma del documento.");
	}

}
