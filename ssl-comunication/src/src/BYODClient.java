package src;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.management.openmbean.InvalidKeyException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class BYODClient {

	static String[] options = { "HMAC SHA MD5", "HMAC SHA 1", "HMAC SHA 256", "HMAC SHA 384", "HMAC SHA 512" };

	public BYODClient()
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException {
		try {
			System.setProperty("javax.net.ssl.trustStore", "C:\\SSLStore");
			System.setProperty("javax.net.ssl.trustStorePassword", "Gi30Se12Gi12Rgio08");
			SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 7070);

			/*
			 * INFO CERTIFICADOS
			 * 
			 */
			SSLSession sesion = socket.getSession();
			System.out.println("Host: " + sesion.getPeerHost());
			X509Certificate certificate = (X509Certificate) sesion.getPeerCertificates()[0];
			System.out.println("Propietario: " + certificate.getSubjectDN());
			System.out.println("Emisor: " + certificate.getIssuerDN());
			System.out.println("Numero Serie: " + certificate.getSerialNumber());
			System.out.println("to string:" + certificate.toString());
			byte[] buf = certificate.getEncoded();
			FileOutputStream os = new FileOutputStream("servidor.cer");
			os.write(buf);
			os.close();
			/* Fin info certificados */

			/* Crea un PrintWriter para enviar mensaje/MAC al servidor */
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
			String mensaje1 = JOptionPane.showInputDialog(null, "Introduzca el username: ");
			String mensaje2 = JOptionPane.showInputDialog(null, "Introduzca la contraseña: ");
			String mensaje3 = JOptionPane.showInputDialog(null, "Introduzca el mensaje: ");
			String mensaje = mensaje1 + "¬" + mensaje2 + "¬" + mensaje3; // TODO hacer el parseado bien y eso
			/* FIN crea un PrintWriter para enviar mensaje/MAC al servidor */

			/*
			 * Devuelve el indice de la opción elegida, y es tratada en la funcion
			 * calculateHMAC.
			 */
			int algoritmo = JOptionPane.showOptionDialog(null,
					"Seleccione el algoritmo a emplear: (Por defecto HMAC SHA 512)", "Click a button",
					JOptionPane.DEFAULT_OPTION, JOptionPane.INFORMATION_MESSAGE, null, options, options[0]);
			output.println(mensaje); // envio del mensaje al servidor
			/* FIN indice de la opción elegida */

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
			String key = secureCore.importPass();
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
			String respuestaLogueo = input.readLine();
			System.out.println("Esta es la respuesta: " + respuestaLogueo);
			if (respuestaLogueo.contains("1")) {
				JOptionPane.showMessageDialog(null, "¡Usuario logueado correctamente!");
			} else if (respuestaLogueo.contains("2")) {
				JOptionPane.showMessageDialog(null, "¡Contraseña incorrecta!");
			} else if (respuestaLogueo.contains("3")) {
				JOptionPane.showMessageDialog(null, "El usuario no existe");
			}
			output.close();
			input.close();
			socket.close();
			/* FIN Parte del codigo para evitar ataques de replay */

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
	public static void main(String args[])
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException {
		new BYODClient();
	}
}