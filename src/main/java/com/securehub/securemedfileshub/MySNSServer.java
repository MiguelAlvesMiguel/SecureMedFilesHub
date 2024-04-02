package com.securehub.securemedfileshub;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;

public class MySNSServer {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java MySNSServer <port>");
            return;
        }
        int port = Integer.parseInt(args[0]);
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server listening on port " + port);

            while (true) {
                try (Socket clientSocket = serverSocket.accept()) {
                    System.out.println("Client connected from " + clientSocket.getInetAddress());
                    processClient(clientSocket);
                } catch (IOException e) {
                    System.err.println("Error handling client connection: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Server could not start: " + e.getMessage());
        }
    }

    private static void processClient(Socket clientSocket) throws IOException {
        DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
        DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
    
        try {
            String command = dis.readUTF();
            switch (command) {
                case "-sc":
                    // Read additional parameters required for -sc command
                    String patientUsername = dis.readUTF();
                    int numberOfFiles = dis.readInt();
                    handleScCommand(dis, dos, patientUsername, numberOfFiles);
                    break;
                case "-sa":
                    handleSaCommand(dis, dos);
                    break;
                case "-se":
                    handleSeCommand(dis, dos);
                    break;
                case "-g":
                    handleGCommand(dis, dos);
                    break;
                default:
                    System.err.println("Unknown command: " + command);
                    dos.writeUTF("Error: Unknown command");
                    break;
            }
        } finally {
            dis.close();
            dos.close();
        }
    }
    
    private static void handleScCommand(DataInputStream dis, DataOutputStream dos, String patientUsername, int numberOfFiles) throws IOException {        // Read patient username and number of files from the input stream
        
    
        Path patientDirectory = Paths.get(patientUsername);
        if (!Files.exists(patientDirectory)) {
            Files.createDirectories(patientDirectory);
        }
    
        for (int i = 0; i < numberOfFiles; i++) {
            String filename = dis.readUTF(); // Read the filename
            int fileLength = dis.readInt(); // Read the file length
            byte[] fileContent = new byte[fileLength];
            dis.readFully(fileContent); // Read the file content
    
            Path filePath = patientDirectory.resolve(filename);
            Files.write(filePath, fileContent); // Save the encrypted file
    
            String keyFilename = dis.readUTF(); // Read the key filename
            int keyLength = dis.readInt(); // Read the key length
            byte[] keyContent = new byte[keyLength];
            dis.readFully(keyContent); // Read the key content
    
            Path keyPath = patientDirectory.resolve(keyFilename);
            Files.write(keyPath, keyContent); // Save the encrypted AES key
        }
    
        dos.writeUTF("Files and keys have been received and saved successfully.");
    }
    

    

    private static void handleSaCommand(DataInputStream dis, DataOutputStream dos) {
        // Placeholder for handling -sa command
    }

    private static void handleSeCommand(DataInputStream dis, DataOutputStream dos) {
        // Placeholder for handling -se command
    }

    private static void handleGCommand(DataInputStream dis, DataOutputStream dos) {
        // Placeholder for handling -g command
    }
}
