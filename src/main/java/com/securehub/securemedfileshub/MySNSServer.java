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
        System.out.println("Server listening on port " + port);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
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
                    handleScCommand(dis, dos);
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
        
    } catch (Exception e) {
        System.err.println("Error processing client request: " + e.getMessage());
        e.printStackTrace();
    }
        finally {
            dis.close();
            dos.close();
        }
    }
    
// Code snippet for handling -sc command inside processClient method
private static void handleScCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    int numberOfFiles = dis.readInt();
    String patientUsername = dis.readUTF();
   

    Path patientDirectory = Paths.get(patientUsername);
    Files.createDirectories(patientDirectory);

    for (int i = 0; i < numberOfFiles; i++) {
        String filename = dis.readUTF();
        int fileLength = dis.readInt();
        byte[] fileContent = new byte[fileLength];
        dis.readFully(fileContent); // Always read the file content

        int keyLength = dis.readInt();
        byte[] keyContent = new byte[keyLength];
        dis.readFully(keyContent); // Always read the encrypted AES key

        Path filePath = patientDirectory.resolve(filename + ".cifrado");
        Path keyPath = patientDirectory.resolve(filename + ".chave_secreta." + patientUsername);

        if (Files.exists(filePath) || Files.exists(keyPath)) {
            dos.writeUTF("Error: File " + filename + ".cifrado or its key already exists on the server.");
        } else {
            Files.write(filePath, fileContent); // Save encrypted file
            Files.write(keyPath, keyContent); // Save encrypted AES key
            dos.writeUTF("Success: File " + filename + ".cifrado and its key saved successfully.");
        }
    }
    dos.writeUTF("END"); // Indicate that all operations for this command are complete
    dos.flush();
}

private static void handleSaCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    int numberOfFiles = dis.readInt();
    String doctorUsername = dis.readUTF();
    String patientUsername = dis.readUTF();
    
    Path patientDirectory = Paths.get(patientUsername);
    Files.createDirectories(patientDirectory);

    for (int i = 0; i < numberOfFiles; i++) {
        String baseFilename = dis.readUTF();
        int fileLength = dis.readInt();
        byte[] fileContent = new byte[fileLength];
        dis.readFully(fileContent); // Read the file content

        int signatureLength = dis.readInt();
        byte[] signatureContent = new byte[signatureLength];
        dis.readFully(signatureContent); // Read the signature content

        Path signedFilePath = patientDirectory.resolve(baseFilename + ".assinado");
        Path signatureFilePath = patientDirectory.resolve(baseFilename + ".assinatura." + doctorUsername);

        if (Files.exists(signedFilePath) || Files.exists(signatureFilePath)) {
            dos.writeUTF("Error: File " + baseFilename + " or its signature already exists on the server.");
        } else {
            Files.write(signedFilePath, fileContent); // Save the signed file
            Files.write(signatureFilePath, signatureContent); // Save the signature
            dos.writeUTF("Success: File " + baseFilename + " and its signature saved successfully.");
        }
        dos.flush(); // Ensure the client receives the response immediately
    }
    dos.writeUTF("END"); // Indicate that all operations for this command are complete
    dos.flush();
}



private static void handleSeCommand(DataInputStream dis, DataOutputStream dos) {
    // Placeholder for handling -se command
}

private static void handleGCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    int numberOfFiles = dis.readInt();
    String patientUsername = dis.readUTF(); // Reading the username for the -g command
   
    Path patientDirectory = Paths.get(patientUsername);

    String[] possibleExtensions = {".cifrado", ".assinado", ".chave_secreta.patient", ".assinatura.doctor"}; // Add other possible extensions here

    for (int i = 0; i < numberOfFiles; i++) {
        String requestedFilename = dis.readUTF();
        System.out.println("Client requested: " + requestedFilename); // Server logging

        boolean fileSent = false;

        for (String ext : possibleExtensions) {
            Path filePath = patientDirectory.resolve(requestedFilename + ext);
            if (Files.exists(filePath)) {
                byte[] fileContent = Files.readAllBytes(filePath);
                System.out.println("Sending file: " + requestedFilename + ext + " Size: " + fileContent.length); // Server logging
                dos.writeUTF(requestedFilename + ext);
                dos.writeInt(fileContent.length);
                dos.write(fileContent);
                dos.flush(); // Flush the stream to ensure all data is sent
                fileSent = true;
                break; // Break after successfully sending the file
            }
        }

        if (!fileSent) {
            dos.writeUTF("Error: File " + requestedFilename + " with expected extensions does not exist on the server.");
            dos.flush(); // Flush to ensure the error message is sent
        }
    }

    dos.writeUTF("END"); // Signal the end of file transmission
    dos.flush(); // Flush the stream to ensure the end message is sent
}




}
