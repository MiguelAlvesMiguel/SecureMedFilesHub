package projetoSI;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class directoryHandlerServer {

	public static List<File> read(String user, List<String> files) throws FileNotFoundException {
		File dir = new File(user+"/");
		if(!dir.exists() || !dir.isDirectory()) {
			throw new FileNotFoundException("Diretoria do utlizador "+user+" não existe.");
		}
		List<File> toRead = new ArrayList<File>();
		for(String filename : files) {
			File temp = new File(user+"/"+filename);
			if(temp.exists()) {
				toRead.add(temp);
			}
		}
		return toRead;
	}

	public static List<File> write(String user, List<String> files) throws IOException {
		File dir = new File(user+"/");
		if(!dir.exists() || !dir.isDirectory()) {
			if(dir.mkdir()) {
				System.out.println("Diretória do utilizador " + user + " não existe. Vai ser agora criada.");
			}
		}
		List<File> toWrite = new ArrayList<File>();
		for(String filename : files) {
			File temp = new File(user+"/"+filename);
			if(temp.createNewFile()) {
				toWrite.add(temp);
			}
		}
		return toWrite;
	}
	
	public static List<String> files(int userID) throws IOException{
		List<String> userFiles = new ArrayList<String>();
		File userDir = new File(String.valueOf(userID) + "/");
		if(!userDir.exists() || !userDir.isDirectory()) {
			if(userDir.mkdir()) {
				System.out.println("Diretória não existe. Utilizador não tem ficheiros no servidor.");
				return null;
			}
		}
		DateFormat date = new SimpleDateFormat("dd-MM-yyyy \t HH:mm");
		for(File temp : userDir.listFiles()) {
			userFiles.add(date.format(new Date(temp.lastModified())) +" \t "+temp.getName());
		}
		return userFiles;
	}
	
	public static void createCertDir() throws IOException{
		File dir = new File("Certificados/");
		if(!dir.exists() || !dir.isDirectory()) {
			if(dir.mkdir()) {
				System.out.println("Diretoria dos Certificados não existe. Vai ser agora criada");
			}
		}
	}
	
	public static boolean createDir(String username) throws IOException {
		File dir = new File(username +"/");
		if(!dir.exists() || !dir.isDirectory()) {
			if(dir.mkdir()) {
				System.out.println("Diretória do utilizador " + username + " não existe. Vai ser agora criada.");
				return true;
			}
		}
		return false;
	}
}
