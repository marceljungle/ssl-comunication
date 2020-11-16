package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Date;

import javax.management.openmbean.InvalidKeyException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class BYODClient {

	static String[] options = { "HMAC SHA MD5", "HMAC SHA 1", "HMAC SHA 256", "HMAC SHA 384", "HMAC SHA 512" };

	public BYODClient() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {

		// Constructor que abre una conexión Socket para enviar mensaje/MAC al

		// servidor
		try {
			System.setProperty("javax.net.ssl.trustStore", "C:\\SSLStore");
			System.setProperty("javax.net.ssl.trustStorePassword", "Gi30Se12Gi12Rgio08");
			SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 7070);
			// crea un PrintWriter para enviar mensaje/MAC al servidor
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
			String mensaje1 = JOptionPane.showInputDialog(null, "Introduzca el username: ");
			String mensaje2 = JOptionPane.showInputDialog(null, "Introduzca la contraseña: ");
			String mensaje3 = JOptionPane.showInputDialog(null, "Introduzca el mensaje: ");
			String mensaje = mensaje1 + " " + mensaje2 + " " + mensaje3; // TODO hacer el parseado bien y eso
			/*
			 * Devuelve el indice de la opción elegida, y es tratada en la funcion
			 * calculateHMAC.
			 */

			int algoritmo = JOptionPane.showOptionDialog(null,
					"Seleccione el algoritmo a emplear: (Por defecto HMAC SHA 512)", "Click a button",
					JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);
			output.println(mensaje); // envio del mensaje al servidor
			// habría que calcular el correspondiente MAC con la clave
			// compartida por servidor/cliente
			String key = secureCore.importPass();

			/*
			 * Parte del codigo para evitar ataques de replay
			 * 
			 * En el caso del cliente, recogemos el valor en milisegundos actual del tiempo
			 * y lo concatenamos al mensaje y calculamos su hmac. Al servidor vamos a
			 * mandarle el mensaje sin la concatenación del tiempo, sin embargo, la hmac si
			 * va a ser el resultado del mensaje concatenado al tiempo.
			 * 
			 * De esta forma, el servidor para poder ver si la hmac coincide, deberá
			 * calcular la hmac probando los 25 valores anteriores del tiempo, si alguno
			 * coincide, significa que la operación es válida.
			 * 
			 * 
			 */

			Long time = Long.parseLong(String.valueOf(new Date().getTime()).substring(0, 12));
			String mensajeTime = mensaje + time;
			String macdelMensaje = secureCore.calculateHMAC(mensajeTime, key, algoritmo);
			output.println(macdelMensaje);
			output.println(algoritmo);
			output.flush();
			// crea un objeto BufferedReader para leer la respuesta del servidor
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String respuesta = input.readLine(); // lee la respuesta del servidor
			JFrame f;
			f = new JFrame();
			System.out.println(respuesta);
			if (respuesta.contains("Mensaje enviado integro")) {
				JOptionPane.showMessageDialog(f, "¡El mensaje ha sido enviado integro!");
			} else {
				JOptionPane.showMessageDialog(f, "¡Mensaje enviado no integro ó hay ataques de replay!");
			}
			output.close();
			input.close();
			socket.close();
		} // end try
		catch (IOException ioException) {
			ioException.printStackTrace();
		}
		// Salida de la aplicacion
		finally {
			System.exit(0);
		}
	}

	// ejecución del cliente de verificación de la integridad
	public static void main(String args[]) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		new BYODClient();
	}
}