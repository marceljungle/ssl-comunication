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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.management.openmbean.InvalidKeyException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class BYODClient {

	static String[] options = { "HMAC SHA MD5", "HMAC SHA 1", "HMAC SHA 256", "HMAC SHA 384", "HMAC SHA 512" };
	static String[] ciphers = {"TLS_AES_128_GCM_SHA256"};
	public BYODClient()
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, CertificateEncodingException {
		try {
			System.setProperty("javax.net.ssl.trustStore", "C:\\SSLStore");
			System.setProperty("javax.net.ssl.trustStorePassword", "Gi30Se12Gi12Rgio08");
			System.setProperty("jdk.tls.client.protocols", "TLSv1.3");
			System.setProperty("https.protocols", "TLSv1.3");
			SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) socketFactory.createSocket("localhost", 7070);
			socket.setEnabledCipherSuites(ciphers);
			
			/* ver los cipher suites usados */
			
			List<String> enCiphersuite=Arrays.asList(socket.getEnabledCipherSuites());
			System.out.println("Los ciphersuites soportados son: "+ enCiphersuite);
			System.out.println("El ciphersuit de la sesión es: "+socket.getSession().getCipherSuite() );
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
			/* FIN crea un PrintWriter para enviar mensaje/MAC al servidor */

			/*
			 * Devuelve el indice de la opción elegida, y es tratada en la funcion
			 * calculateHMAC.
			 */
			output.println(mensaje3); // envio del mensaje al servidor
			output.println(mensaje1); // envio del mensaje al servidor
			output.println(mensaje2); // envio del mensaje al servidor
			/* FIN indice de la opción elegida */

			
			output.flush();
			// crea un objeto BufferedReader para leer la respuesta del servidor
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String respuestaLogueo = input.readLine();
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