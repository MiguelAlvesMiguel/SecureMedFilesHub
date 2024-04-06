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


private static void handleSeCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    try {
        int numberOfFiles = dis.readInt();
        String patientUsername = dis.readUTF();
        String doctorUsername = dis.readUTF();
        
        Path patientDirectory = Paths.get(patientUsername);
        Files.createDirectories(patientDirectory);

        for (int i = 0; i < numberOfFiles; i++) {
            String filename = dis.readUTF();
            int encryptedFileLength = dis.readInt();
            byte[] encryptedFileBytes = new byte[encryptedFileLength];
            dis.readFully(encryptedFileBytes);

            int encryptedAesKeyLength = dis.readInt();
            byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
            dis.readFully(encryptedAesKey);

            int signedFileLength = dis.readInt();
            byte[] signedFileBytes = new byte[signedFileLength];
            dis.readFully(signedFileBytes);

            int signatureLength = dis.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);
            
            int fileLength = dis.readInt();
            byte[] fileContent = new byte[fileLength];
            dis.readFully(fileContent); // Read the file content

            Path encryptedFilePath = patientDirectory.resolve(filename + ".cifrado");
            Path aesKeyPath = patientDirectory.resolve(filename + ".chave_secreta." + patientUsername);
            Path signedFilePath = patientDirectory.resolve(filename + ".seguro");
            Path signaturePath = patientDirectory.resolve(filename + ".assinatura." + doctorUsername);
            Path signedPath = patientDirectory.resolve(filename + ".assinado");


            if (Files.exists(encryptedFilePath) || Files.exists(aesKeyPath) || Files.exists(signedFilePath) || Files.exists(signaturePath) || Files.exists(signedPath)) {
                dos.writeUTF("Error: One or more files already exist on the server.");
            } else {
                Files.write(encryptedFilePath, encryptedFileBytes); // Save encrypted file
                Files.write(aesKeyPath, encryptedAesKey); // Save encrypted AES key
                Files.write(signedFilePath, signedFileBytes); // Save signed file
                Files.write(signaturePath, signatureBytes); // Save signature
                Files.write(signedPath, signedFileBytes);
                dos.writeUTF("Success: Files saved successfully.");
            }
            dos.flush(); // Ensure the client receives the response immediately
        }
        dos.writeUTF("END"); // Indicate that all operations for this command are complete
        dos.flush();
    } catch (IOException e) {
        e.printStackTrace();
        dos.writeUTF("Error: An error occurred while processing the command."); // Notify client of failure
        dos.flush();
    }
}


private static void handleGCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    int numberOfFiles = dis.readInt(); // Read the number of files
    String patientUsername = dis.readUTF(); // Read the username

    Path patientDirectory = Paths.get(patientUsername);

    for (int i = 0; i < numberOfFiles; i++) {
        String requestedFilename = dis.readUTF(); // Read the requested filename

        Path fileCifrado = patientDirectory.resolve(requestedFilename + ".cifrado");
        Path keyFile = patientDirectory.resolve(requestedFilename + ".chave_secreta." + patientUsername);
        Path fileAssinado = patientDirectory.resolve(requestedFilename + ".assinado");
        Path signatureFile = patientDirectory.resolve(requestedFilename + ".assinatura.doctor");

        // Check for encrypted files and keys
        if (Files.exists(fileCifrado) && Files.exists(keyFile)) {
            sendFileContentAndKey( dos, fileCifrado, keyFile);
        }
        // Check for signed files and signatures
         if (Files.exists(fileAssinado) && Files.exists(signatureFile)) {
            System.out.println("Sending signed file and signature");
            sendFileContentAndSignature( dos, fileAssinado, signatureFile);
        } else {
            System.out.println(".assinado File not found");
            dos.writeBoolean(false); // File does not exist
        }
        dos.flush(); // Flush the stream after each file
    }

    dos.writeUTF("END"); // Signal the end of file transmission
    dos.flush();
}

private static void sendFileContentAndKey(DataOutputStream dos, Path fileCifrado, Path keyFile) throws IOException {
    dos.writeBoolean(true); // File exists
    dos.writeUTF(fileCifrado.getFileName().toString()); // Send file name with extension

    // Send the file content
    byte[] fileContent = Files.readAllBytes(fileCifrado);
    dos.writeInt(fileContent.length);
    dos.write(fileContent);

    // Send the key content
    byte[] keyContent = Files.readAllBytes(keyFile);
    dos.writeInt(keyContent.length);
    dos.write(keyContent);
}

private static void sendFileContentAndSignature(DataOutputStream dos, Path fileAssinado, Path signatureFile) throws IOException {
    dos.writeBoolean(true); // Signed file exists
    dos.writeUTF(fileAssinado.getFileName().toString()); // Send file name with extension

    // Send the signed file content
    byte[] signedFileContent = Files.readAllBytes(fileAssinado);
    dos.writeInt(signedFileContent.length);
    dos.write(signedFileContent);

    // Send the signature content
    byte[] signatureContent = Files.readAllBytes(signatureFile);
    dos.writeInt(signatureContent.length);
    dos.write(signatureContent);
}



private static void sendEncryptedFileWithKey(DataOutputStream dos, Path patientDirectory, String filename, String patientUsername) throws IOException {
    // Send encrypted file
    Path filePath = patientDirectory.resolve(filename);
    byte[] fileContent = Files.readAllBytes(filePath);
    dos.writeInt(fileContent.length);
    dos.write(fileContent);

    // Send encrypted AES key
    Path keyPath = patientDirectory.resolve(filename.replace(".cifrado", ".chave_secreta." + patientUsername));
    if (Files.exists(keyPath)) {
        byte[] keyContent = Files.readAllBytes(keyPath);
        dos.writeInt(keyContent.length);
        dos.write(keyContent);
    } else {
        dos.writeInt(0); // No key found, send 0 length
    }
}

private static void sendSignedFileWithSignature(DataOutputStream dos, Path patientDirectory, String filename) throws IOException {
    // Implementation for sending signed file along with its signature
    // Similar to sendEncryptedFileWithKey but tailored for signed files
    //TODO dps 
}





}
