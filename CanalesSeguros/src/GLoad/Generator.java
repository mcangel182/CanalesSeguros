package GLoad;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import uniandes.gload.core.*;
import uniandes.gload.examples.clientserver.generator.ClientServerTask;

public class Generator {

	private LoadGenerator generator;
	public static int numTransPerdidas;
	public static File archivoResultados;
	public static FileWriter escritoArchivo;

	public Generator(){

		numTransPerdidas=0;
		Task work = createTask();
		int numberOfTasks = 400;
		int gapBetweenTasks = 20;
		archivoResultados = new File("./data/resultados.csv");
		generator = new LoadGenerator("", numberOfTasks, work, gapBetweenTasks);
		generator.generate();
		try {
			Thread.sleep(30000);
			escritoArchivo = new FileWriter(archivoResultados, true);
			escritoArchivo.write("Transacciones perdidas = "+numTransPerdidas+"\n");
			escritoArchivo.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private Task createTask(){
		return new ClienteTask();
	}

	public static void main(String[] args) {
		Generator gen = new Generator();
	}

}
