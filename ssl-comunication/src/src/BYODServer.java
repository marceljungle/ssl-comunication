package src;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
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
	static String[] ciphers = {"TLS_AES_128_GCM_SHA256"};
	// Constructor
	public BYODServer() throws Exception {
		// ServerSocketFactory para construir los ServerSockets
		System.setProperty("javax.net.ssl.keyStore", "C:\\SSLStore");
		System.setProperty("javax.net.ssl.keyStorePassword", "Gi30Se12Gi12Rgio08");
		SSLServerSocketFactory socketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		// creación de un objeto ServerSocket (se establece el puerto)
		serverSocket = (SSLServerSocket) socketFactory.createServerSocket(7070);
		//serverSocket.setEnabledCipherSuites(ciphers);
		List<String> enCiphersuite=Arrays.asList(serverSocket.getEnabledCipherSuites());
		System.out.println("Los ciphersuites soportados son: "+ enCiphersuite);
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
				String usuario = input.readLine();
				String contraseña = input.readLine();
				
				
				/* Comprobar usuario + Logging + logging stats*/
				CheckUsers map = new CheckUsers();
				Map<String, String> dict = map.CSVReader();
				dict = map.CSVReader();
				List<Integer> stats = secureCore.readStats();
				if (dict.containsKey(usuario)) {
					if (dict.containsValue(contraseña)) {
						output.println("1");
						LOGGER.log(Level.INFO, "Usuario logueado");
						secureCore.writeStats("successfull", String.valueOf(stats.get(0) + 1));
					} else {
						output.println("2");
						LOGGER.log(Level.WARNING, "¡Error en el logueo del usuario!");
						secureCore.writeStats("unsuccessfull", String.valueOf(stats.get(1) + 1));
					}

				} else {
					output.println("3");
					LOGGER.log(Level.WARNING, "¡Error en el logueo del usuario!");
					secureCore.writeStats("unsuccessfull", String.valueOf(stats.get(1) + 1));
				}
				System.out.println(mensaje);
				
				/* FIN Comprobar usuario + Logging + logging stats */
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