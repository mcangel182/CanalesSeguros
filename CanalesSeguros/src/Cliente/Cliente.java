package Cliente;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import Seguridad.*;

/**
 * La clase Cliente.
 */
public class Cliente {
	
	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------

	public final static String SEPARADOR = ":";
	
	public final static String HOLA = "HOLA";
	
	public final static String ACK = "ACK";
	
	public final static String ALGORITMOS = "ALGORITMOS";
	
	public final static String ALG_SIM = "AES";
	
	public final static String ALG_ASIM = "RSA";
	
	public final static String ALG_HMAC = "HMACMD5";
	
	public final static String STATUS = "STATUS";
	
	public final static String OK = "OK";
	
	public final static String ERROR = "ERROR";
	
	public final static String CERTSRV = "CERTSRV";
	
	public final static String CERTCLNT = "CERCLNT";
	
	public final static String INIT = "INIT";
	
	public final static String INFO = "INFO";
	
	public final static String SEPARADOR_LOGIN = ",";
	
	// -----------------------------------------------------------------
	// Atributos
	// -----------------------------------------------------------------	
	
	/** Dirección IP del servidor. */
	private String ipServidor;
	
	/** Puerto del servidor. */
	private int puerto;
	
	/** Lector de caracteres. */
	private BufferedReader in;
	
	/** Lector de bytes */
	private InputStream inputStream;
	
	/** Escritor de caracteres. */
	private PrintWriter out;
	
	/** Escritor de bytes. */
	private OutputStream outputStream;
	
	/** Llave pública del servidor. */
	private PublicKey llavePublicaServidor;
	
	/** Par de llaves (privada y publica) del cliente. */
	private KeyPair llavesCliente;
	
	/** Llave secreta para el cifrado simétrico. */
	private SecretKey llaveSecreta;
	
	/** Socket para la comunicación con el servidor */
	private Socket socket;
	
	// -----------------------------------------------------------------
	// Constructores
	// -----------------------------------------------------------------
	
	/**
	 * Método para instanciar un nuevo cliente.
	 */
	public Cliente(){
		ipServidor = "infracomp.virtual.uniandes.edu.co";
		puerto = 443;
		inicializarLlavesCliente();
	}
	
	/**
	 * Método que genera e inicializa las llaves (pública y privada) del cliente.
	 */
	private void inicializarLlavesCliente(){
		try {
			KeyPairGenerator generator;
			generator = KeyPairGenerator.getInstance(ALG_ASIM);
			generator.initialize(1024);
			llavesCliente = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	// -----------------------------------------------------------------
	// Metodos
	// -----------------------------------------------------------------
	
	/**
	 * Metodo que gestiona la comunicación entre el cliente y el servidor 
	 * @param datos Los datos correspondientes a la afiliación
	 */
	public void comunicarse(String datos){
		iniciarConexion();
		if(!handshake()){
			System.out.println("Termina en handshake");
		}
		// Etapa 1: seleccionar algoritmos.
		if(!algoritmos()){
			System.out.println("Termina en Algoritmos");
		}
		// Etapa 2: autenticación del servidor.
		if(!autenticacionServidor()){
			System.out.println("Termina en Autenticación del Servidor");
		}
		// Etapa 3: autenticación del cliente.
		if(!autenticacionCliente()){
			System.out.println("Termina en Autenticación del Cliente");
		}
		// Etapa 4: envio de información
		if(!llaveSimetrica()){
			System.out.println("Termina en Llave Simetrica");
		}
		if(!enviarInfo(datos)){
			System.out.println("Termina en Enviar Datos");
		}
		close();
	}
	
	/**
	 * Método que inicializa la conexxión con el servidor. 
	 */
	public void iniciarConexion(){
		try {
			socket = new Socket(ipServidor, puerto);
			inputStream = socket.getInputStream();
			in = new BufferedReader(new InputStreamReader(inputStream));
			outputStream = socket.getOutputStream();
			out = new PrintWriter(outputStream,true);		
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Método que se encarga de hacer el handshake entre el cliente y el servidor.
	 * Retorna true si se realizó el handshake con éxito.
	 * @return true, si el handshake fue exitoso; false de lo contrario. 
	 */
	public boolean handshake(){
		try {
			out.println(HOLA);
			String respuesta = in.readLine();
			if(respuesta.equals(ACK)){
				return true;
			}
		} catch (Exception e) {
			System.err.println("Handshake Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	/**
	 * Método que se encarga de mandar los algoritmos que usuará el cliente duante la comunicación con el servidor.
	 * Retorna true si se envió la información de los algoritmos con éxito. 
	 * @return true, si se envían los algoritmos con éxito; false de lo contrario. 
	 */
	public boolean algoritmos(){
		try {
			out.println(ALGORITMOS + SEPARADOR + ALG_SIM + SEPARADOR + ALG_ASIM + SEPARADOR + ALG_HMAC);
			String respuesta = in.readLine();
			if(respuesta.equals(STATUS + SEPARADOR + OK)){
				return true;
			}
		} catch (Exception e) {
			System.err.println("Algoritmos Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	/**
	 * Método que se encarga de realizar la autenticacion del  servidor.
	 * Retorna true si el servidor se autentico ante el cliente con éxito.
	 * @return true, si el servidor se atentica con éxito; false de lo contrario.
	 */
	public boolean autenticacionServidor(){
		String cert;
		try {
			cert = in.readLine();
			if (cert.equals(CERTSRV)){
				byte[] certificadoServidor = new byte[1024];
				inputStream.read(certificadoServidor); 
				llavePublicaServidor = CertificadoDigital.darLlavePublica(certificadoServidor);
				return true;
			}
		} catch (IOException e) {
			System.err.println("Autenticación Servidor Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	/**
	 * Método que se encarga de realizar la autenticacion del cliente.
	 * Retorna true si el cliente se autentico ante el servidor con éxito.
	 * @return true, si el cliente se atentica con éxito; false de lo contrario.
	 */
	public boolean autenticacionCliente(){
		try {
			out.println(CERTCLNT);
			X509Certificate certificado = CertificadoDigital.generarCertificado(llavesCliente);
			byte[] cert = certificado.getEncoded();
			outputStream.write(cert);
			outputStream.flush();
			return true;
		} catch (Exception e) {
			System.err.println("Autenticación Cliente Exception: " + e.getMessage()); 
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Método que se encarga de recibir la llave simétrica y confirmar que llego bien
	 * Retorna true si el servidor confirma la interpretación de la llave simétrica. 
	 * @return true, si se confirma la llave secreta; false de lo contrario.
	 */
	public boolean llaveSimetrica(){
		try {
			String mensaje = in.readLine();
			String[] partesMensaje = mensaje.split(SEPARADOR);
			if(partesMensaje[0].equals(INIT)){
				byte [] llaveSecretaEcriptada = Transformacion.destransformar(partesMensaje[1]);
				byte [] llaveSecretaEnBytes = CifradoAsimetrico.descifrar(llavesCliente.getPrivate(), llaveSecretaEcriptada);
				llaveSecreta = new SecretKeySpec(llaveSecretaEnBytes, 0, llaveSecretaEnBytes.length, "AES");
				out.println(INIT + SEPARADOR + Transformacion.transformar(CifradoAsimetrico.cifrarConPublica(llavePublicaServidor, llaveSecretaEnBytes)));
				String respuesta = in.readLine();
				if (respuesta.equals(STATUS + SEPARADOR + OK)){
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println("Autenticación Cliente Exception: " + e.getMessage()); 
		}
		return false;
	}
	
	/**
	 * Método que envía la información correspondiente a la afiliación. 
	 * Retorna true si se envía la información con éxito. 
	 * @param datos Los datos correpondientes a la afiliación. 
	 * @return true, si se envían los datos con éxito; false de lo contrario. 
	 */
	public boolean enviarInfo(String datos){	
		byte[] datosEnBytes = datos.getBytes();
		byte[] datosCifrados = CifradoSimetrico.cifrar(llaveSecreta, datosEnBytes);
		String datosTransformados = Transformacion.transformar(datosCifrados);
		out.println(INFO + SEPARADOR + datosTransformados);
		
		byte[] hashDatos = ResumenDigital.calcular(datos, llaveSecreta.getEncoded());
		byte[] hashDatosCifrado = CifradoAsimetrico.cifrarConPrivada(llavesCliente.getPrivate(), hashDatos);
		String hashTransformado = Transformacion.transformar(hashDatosCifrado);
		out.println(INFO + SEPARADOR + hashTransformado);
		
		try {
			String mensaje = in.readLine();
			String[] partesMensaje = mensaje.split(SEPARADOR);
			if(partesMensaje[0].equals(INFO)){
				String rtaCifrada = partesMensaje[1];
				byte [] rtaDescifrada = CifradoSimetrico.descifrar(Transformacion.destransformar(rtaCifrada), llaveSecreta);
				String rta = new String(rtaDescifrada);
				System.out.println(rta);
				if (rta.equals(OK)){
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println("Autenticación Cliente Exception: " + e.getMessage()); 
			e.printStackTrace();
		}
		
		return false;
	}
	
	/**
	 * Método encargado de cerrar toda la comunicación con el servidor.
	 */
	private void close() {
		try {
			in.close();
			out.close();
			inputStream.close();
			outputStream.close();
			socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// -----------------------------------------------------------------
	// Main
	// -----------------------------------------------------------------
	
	/**
	 * Método Main.
	 * Se encarga de solicitar los datos requeridos e iniciar la comunicación con el servidor
	 * @param args Argumentos del main.
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String datos = null;
		
		BufferedReader lector = new BufferedReader(new InputStreamReader(System.in)); 
		
		try {
			System.out.println("Datos: ");
			datos = lector.readLine();
		} catch (IOException e) {
			System.err.println("Datos Exception: " + e.getMessage());
			System.exit(1);
		}
		
		Cliente cliente = new Cliente();
		cliente.comunicarse(datos);
	}

}
