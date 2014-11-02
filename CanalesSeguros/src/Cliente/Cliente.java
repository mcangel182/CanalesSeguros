package Cliente;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import GLoad.Generator;
import Seguridad.*;

/**
 * La clase Cliente.
 */
public class Cliente {
	
	// -----------------------------------------------------------------
	// Constantes
	// -----------------------------------------------------------------

	/** Constante que representa el separador de los mensajes del protocolo. */
	public final static String SEPARADOR = ":";
	
	/** Constante que representa el saludo del cliente al servidor. */
	public final static String HOLA = "HOLA";
	
	/** Constante que representa el acknowledge del servidor al cliente. */
	public final static String ACK = "ACK";
	
	/** Constante que representa la cadena de control algooritmos. */
	public final static String ALGORITMOS = "ALGORITMOS";
	
	/** Constante que representa el algorimo simétrico. */
	public final static String ALG_SIM = "AES";
	
	/** Constante que representa el algoritmo asimétrico. */
	public final static String ALG_ASIM = "RSA";
	
	/** Constante que representa el algoritmo para calcular el HMAC. */
	public final static String ALG_HMAC = "HMACMD5";
	
	/** Constante que representa la cadena de control status. */
	public final static String STATUS = "STATUS";
	
	/** Constante que representa la cadena de control ok. */
	public final static String OK = "OK";
	
	/** Constante que representa la cadena de control error. */
	public final static String ERROR = "ERROR";
	
	/** Constante que representa la cadena de control certsrv. */
	public final static String CERTSRV = "CERTSRV";
	
	/** Constante que representa la cadena de control certclnt. */
	public final static String CERTCLNT = "CERCLNT";
	
	/** Constante que representa la cadena de control init. */
	public final static String INIT = "INIT";
	
	/** Constante que representa la cadena de control info. */
	public final static String INFO = "INFO";
	
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
//		ipServidor = "infracomp.virtual.uniandes.edu.co";
//		puerto = 443;
		ipServidor = "localhost";
		puerto = 5555;
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
	// Métodos
	// -----------------------------------------------------------------
	
	/**
	 * Metodo que gestiona la comunicación entre el cliente y el servidor 
	 * @param datos Los datos correspondientes a la afiliación
	 */
	public void comunicarse(String datos){
		iniciarConexion();
		boolean hayError = false;
		if(!handshake()){
			hayError=true;
		}
		// Etapa 1: seleccionar algoritmos.
		if(!hayError && !algoritmos()){
			hayError=true;
		}
		// Etapa 2: autenticación del servidor.
		if(!hayError && !autenticacionServidor()){
			hayError=true;
		}
		// Etapa 3: autenticación del cliente.
		if(!hayError && !autenticacionCliente()){
			hayError=true;
		}
		// Etapa 4: envio de información
		if(!hayError && !llaveSimetrica()){
			hayError=true;
		}
		if(!hayError && !enviarInfo(datos)){
			hayError=true;
		}
		if(hayError){
			System.out.println("hubo error");
			Generator.numTransPerdidas++;
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
			System.err.println("Conexión Exception: " + e.getMessage()); 
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
		} catch (Exception e) {
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
			System.err.println("Llave Simétrica Exception: " + e.getMessage()); 
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
		
		long tiempoInic = System.currentTimeMillis();
		
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
				byte [] rtaDescifrada = CifradoSimetrico.descifrar(llaveSecreta, Transformacion.destransformar(rtaCifrada));
				String rta = new String(rtaDescifrada);
				//System.out.println(rta);
				if (rta.equals(OK)){
					long tiempoFin = System.currentTimeMillis();
					long tiempoRespuestaPedido = tiempoFin-tiempoInic;
					//System.out.println(""+tiempoRespuestaPedido);
					Generator.escritoArchivo = new FileWriter(Generator.archivoResultados, true);
					Generator.escritoArchivo.write(tiempoRespuestaPedido+"\n");
					Generator.escritoArchivo.close();
					return true;
				}
			}
		} catch (Exception e) {
			System.err.println("Enviar Información Exception: " + e.getMessage()); 
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
			System.err.println("Close Exception: " + e.getMessage()); 
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
