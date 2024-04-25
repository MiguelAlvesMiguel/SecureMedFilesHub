package projetoSI;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class userFile extends errorable{
	
	private static userFile instance = null;
	private HashMap<String, String> userMap = new HashMap<String, String>();
	private File userfile;

	private userFile(String pathname) throws Exception {
		userfile = new File(pathname);
		if (!userfile.exists()) {
			try {
				FileWriter writer = new FileWriter(userfile);
				writer.write("admin;badpw\n");
				writer.flush();
				writer.close();
			} catch (IOException e) {
				error("Ficheiro de utilizadores n„o existe nem pode ser carregado.");
			}
		}
		Scanner reader = new Scanner(userfile);
		if (!reader.hasNext()) {
			error("Ficheiro de utilizadores encontra-se vazio.\nO Ficheiro n„o ser· carregado.");
		}
		boolean first=true;
		while (reader.hasNext()) {
			String line = reader.next();
			if (line.matches("[\\w\\s]*;\\S*$")) {
				String[] user_args = line.split(";");
				if(first) {
					if (!user_args[0].equals("admin")) {
						error("Ficheiro de utilizadores tem dados inv·lidos ou foi corrompido."
								+ "\nO Ficheiro n„o ser· carregado.");
					}
					first = false;
				}
				if (userMap.containsKey(user_args[0])) {
					error("Ficheiro de utilizadores tem dados inv·lidos.(2 ou mais utilizadores com o mesmo username)"
							+ "\nO Ficheiro n„o ser· carregado.");
				}
				userMap.put(user_args[0], user_args[1]);
			} else {
				error("Ficheiro de utilizadores tem dados inv·lidos ou foi corrompido."
						+ "\nO Ficheiro n„o ser· carregado.");
			}

		}
		reader.close();
	}


	public static userFile getFile(String pathname) throws Exception {
		if (instance == null) {
			instance = new userFile(pathname);
		}
		return instance;
	}

	public boolean newUser(String name, String passwd) throws IOException {
		if (!userMap.containsKey(name)) {
			FileWriter writer = new FileWriter(userfile, true);
			writer.write(name + ";" + passwd + "\n");
			
			/*
			//  Gerar um salt aleat√≥rio
				SecureRandom random = new SecureRandom();
		        byte[] salt = new byte[16];
		        random.nextBytes(salt);
		        String saltString = Base64.getEncoder().encodeToString(salt);
		        
		        // Combina a senha com o salt
		        String saltedPassword = passwd + Base64.getEncoder().encodeToString(salt);
		        
		        // Criar o hash SHA-256
		        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		        byte[] hash = messageDigest.digest(saltedPassword.getBytes());
		        
		        String hashString = Base64.getEncoder().encodeToString(hash);
		        
				userMap.put(name, hashString, saltString);
			*/
			
			userMap.put(name, passwd);
			writer.close();
			return true;
			
		}
		return false;
	}

	public boolean authUser(String name, String passwd) {
		if(userMap.containsKey(name)) {
			String pwd = userMap.get(name);
			return pwd.equals(passwd);
		} else {
			return false;
		}
		
		/*
		 * String saltedPassword = passwd + userMap.get(saltString);
		
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] hash = messageDigest.digest(saltedPassword.getBytes());
        
        String generatedHash = Base64.getEncoder().encodeToString(hash);
		
		if(userMap.containsKey(name)) {
			String pwd = userMap.get(name);
			return generateHash.equals(userMap.get(hashString));
		} else {
			return false;
		}
		 */
		
	}
	
	/*
	public String toString() {
		String users = "";
		for (int i : userMap.keySet()) {
			List<String> user = userMap.get(i);
			users += i + ";" + user.get(0) + ";" + user.get(1);
		}
		return users;
	}
	*/
	
	private static Random rand = new Random((new Date().getTime()));
	
	public static byte[] encrypt(String encstr) {
		
		byte[] salt = new byte[8];
		rand.nextBytes(salt);
		
		return Base64.getEncoder().encode(encstr.getBytes());
		
	}
	
    public static byte[] decrypt(String encstr) {
		
		String cipher = encstr.substring(12);
		
		return Base64.getDecoder().decode(cipher.getBytes());
		
	}




	
}
