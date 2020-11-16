package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.management.openmbean.InvalidKeyException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class BYODServer {

	private SSLServerSocket serverSocket;
	private final static Logger LOGGER = Logger.getLogger(BYODClient.class.getName());

	// Constructor
	public BYODServer() throws Exception {
		// ServerSocketFactory para construir los ServerSockets
		System.setProperty("javax.net.ssl.keyStore", "C:\\SSLStore");
		System.setProperty("javax.net.ssl.keyStorePassword", "Gi30Se12Gi12Rgio08");
		SSLServerSocketFactory socketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		// creación de un objeto ServerSocket (se establece el puerto)
		serverSocket = (SSLServerSocket) socketFactory.createServerSocket(7070);
	}

	// ejecución del servidor para escuchar peticiones de los clientes
	private void runServer() throws InvalidKeyException, SignatureException, NoSuchAlgorithmException,
			SecurityException, IOException, CertificateEncodingException {

		LOGGER.setLevel(Level.INFO);
		Handler fileHandler = new FileHandler("logfile.log", true);
		SimpleFormatter sformatter = new SimpleFormatter();
		fileHandler.setFormatter(sformatter);
		LOGGER.addHandler(fileHandler);
		while (true) {
			// espera las peticiones del cliente para comprobar mensaje/MAC

			try {

				LOGGER.log(Level.INFO, "Servidor a la espera de clientes");
				System.err.print("Esperando conexiones de clientes...");
				SSLSocket socket = (SSLSocket) serverSocket.accept();
				// abre un BufferedReader para leer los datos del cliente
				BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				// abre un PrintWriter para enviar datos al cliente
				PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
				// se lee del cliente el mensaje y el macdelMensajeEnviado

				String mensaje = input.readLine();
				String macdelMensajeEnviado = input.readLine();
				String key = secureCore.importPass();
				Integer algo = Integer.parseInt(input.readLine());

				/*
				 * Parte del codigo para evitar el replay
				 * 
				 * Mediante el valor del tiempo que recogemos en el servidor, entramos en un
				 * bucle y comprobamos los 25 milisegundos anteriores concatenandolos al mensaje
				 * y sacando la hmac que le corresponde. Si en alguno de los valores conincide,
				 * significa que la operación es válida. En caso de que no conincida, podemos
				 * estar ante un caso de ataque por replay o simplemente la solicitud ha tardado
				 * demasiado en llegar al servidor.
				 * 
				 */
				String cadena;
				String macdelMensajeCalculado;
				Long time = Long.parseLong(String.valueOf(new Date().getTime()).substring(0, 12));
				long newTime;
				int succeed = 0; // si 0, no ha salido bien
				for (int i = 0; i < 50; i++) {
					newTime = time - i;
					cadena = mensaje + newTime;
					macdelMensajeCalculado = secureCore.calculateHMAC(cadena, key, algo);
					// a continuación habría que verificar el MAC
					if (macdelMensajeEnviado.equals(macdelMensajeCalculado)) {
						LOGGER.log(Level.INFO, "Mensaje enviado integro");
						output.println("Mensaje enviado integro");
						System.err.println(mensaje);
						succeed = 1;
						break;
					}
				}
				if (succeed == 0) {
					LOGGER.log(Level.WARNING, "Mensaje enviado no integro ó hay ataques de replay");
					output.println("Mensaje enviado no integro ó hay ataques de replay ");
				}
				/* FIN Parte del codigo para evitar el replay */

				/*
				 * Seguimiento de los mensajes enviados (estadística)
				 * 
				 */
				List<Integer> stats = secureCore.readStats();
				if (succeed == 1) {
					secureCore.writeStats("successfull", String.valueOf(stats.get(0) + 1));
					LOGGER.log(Level.INFO, "Cantidad de mensajes integros: " + String.valueOf(stats.get(0) + 1));
					LOGGER.log(Level.INFO,
							"Cantidad total de mensajes: " + String.valueOf(stats.get(0) + 1 + stats.get(1)));
				} else {
					secureCore.writeStats("unsuccessfull", String.valueOf(stats.get(1) + 1));
					LOGGER.log(Level.INFO, "Cantidad de mensajes integros: " + String.valueOf(stats.get(0) + 1));
					LOGGER.log(Level.INFO,
							"Cantidad total de mensajes: " + String.valueOf(stats.get(0) + stats.get(1) + 1));
				}
				output.close();
				input.close();
				socket.close();
				fileHandler.close();
				LOGGER.removeHandler(fileHandler);
			} catch (IOException ioException) {
				ioException.printStackTrace();
			}
		}
	}

	// ejecucion del servidor
	public static void main(String args[]) throws Exception {
		BYODServer server = new BYODServer();
		server.runServer();
	}
}