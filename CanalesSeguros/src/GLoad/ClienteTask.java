package GLoad;

import Cliente.Cliente;
import uniandes.gload.core.Task;

public class ClienteTask extends Task{

	@Override
	public void fail() {
		// TODO Auto-generated method stub
        System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		// TODO Auto-generated method stub
        System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() {
		// TODO Auto-generated method stub
		Cliente cliente =  new Cliente();
		cliente.comunicarse("HOLA ESTO ES UNA PRUEBA!");		
	}

}
