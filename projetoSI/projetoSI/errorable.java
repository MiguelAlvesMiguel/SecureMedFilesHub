package projetoSI;

public class errorable {
	
	public static void error(final String message,final int excode) {
		System.err.println(message);
		System.exit(excode);
	}

	public static void error(final String message) {
		error(message,1);
	}
	
}

