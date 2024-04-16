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

    String patientUsername = dis.readUTF();
   

    Path patientDirectory = Paths.get(patientUsername);
    Files.createDirectories(patientDirectory);

    for (int i = 0; i < numberOfFiles; i++) {
        String signedFileName = dis.readUTF();
        int signedFileLength = dis.readInt();
        byte[] signedFileContent = new byte[signedFileLength];
        dis.readFully(signedFileContent); // Read the signed file content

        String signatureFileName = dis.readUTF();
        int signatureLength = dis.readInt();
        byte[] signatureContent = new byte[signatureLength];
        dis.readFully(signatureContent); // Read the signature content

        Path signedFilePath = patientDirectory.resolve(signedFileName);
        Path signatureFilePath = patientDirectory.resolve(signatureFileName);

        if (Files.exists(signedFilePath) || Files.exists(signatureFilePath)) {
            dos.writeUTF("Error: File " + signedFileName + " or its signature already exists on the server.");
        } else {
            Files.write(signedFilePath, signedFileContent); // Save the signed file
            Files.write(signatureFilePath, signatureContent); // Save the signature
            dos.writeUTF("Success: File " + signedFileName + " and its signature saved successfully.");
        }
        dos.flush(); // Ensure the client receives the response immediately
    }
    dos.writeUTF("END"); // Indicate that all operations for this command are complete
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
    int numberOfFiles = dis.readInt();
    String patientUsername = dis.readUTF();

    Path patientDirectory = Paths.get(patientUsername);

    for (int i = 0; i < numberOfFiles; i++) {
        System.out.println("Requesting file " + (i + 1) + " of " + numberOfFiles);
        String requestedFilename = dis.readUTF();
        String fileExtension = getFileExtension(requestedFilename);
        Boolean foundExtension = !fileExtension.isEmpty();
        if (fileExtension.isEmpty()) {
            System.out.println("Security extension not recognized for file: " + requestedFilename+ " finding safest form...");
        }

        System.out.println("Requested file: " + requestedFilename + " with extension: " + fileExtension);
        Path fileToSend = getFileToSend(patientDirectory, requestedFilename, foundExtension, patientUsername);
        System.out.println("File to send: " + fileToSend);

       //Print all files in the directory

       System.out.println("Files in directory: ");
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(patientDirectory)) {
            for (Path entry : stream) {
                System.out.println(entry.getFileName());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (Files.exists(patientDirectory.resolve(requestedFilename))) {
        System.out.println("File Exists! Sending file...  " + fileToSend.getFileName());
            dos.writeBoolean(true); // File exists
             //If the extension was previously empty, send the file name with extension to the client
        if(fileExtension.isEmpty()){
            //Send file name with extension to client
            System.out.println("Sending file name with extension to client: " + fileToSend.getFileName());
            dos.writeUTF(fileToSend.getFileName().toString());
        }
            sendFile(dos, fileToSend, patientUsername);
        } else {
            dos.writeBoolean(false); // File does not exist
        }
        dos.flush();
    }

    dos.writeUTF("END");
    dos.flush();
}

private static String getFileExtension(String filename) {
    if (filename.endsWith(".cifrado") || filename.endsWith(".assinado") || filename.endsWith(".seguro")) {
        return filename.substring(filename.lastIndexOf("."));
    }
    return ""; // Default to no extension if not recognized
}

private static Path getFileToSend(Path directory, String filename, boolean foundExtension, String username) {
    if (foundExtension) {
        Path filePath = directory.resolve(filename);
        if (Files.exists(filePath)) {
            return filePath.getFileName();
        } else {
            System.out.println("File not found: " + filePath);
        }
    }

    // If no extension specified, default to the safest form
    System.out.println("EXTENSION EMPTY, finding safest extension... " + filename);
    System.out.println("directory passed in params: " + directory);

    String baseName = filename; // Assuming filename comes without extension if extension is not recognized

    Path seguro = directory.resolve(baseName + ".seguro");
    if (Files.exists(seguro)) {
        return seguro.getFileName();
    }

    Path cifrado = directory.resolve(baseName + ".cifrado");
    if (Files.exists(cifrado)) {
        return cifrado.getFileName();
    }

    Path assinado = directory.resolve(baseName + ".assinado");
    if (Files.exists(assinado)) {
        return assinado.getFileName();
    }

    // If no matching file is found, return null or throw an exception
    System.out.println("No matching file found for: " + filename);
    return null; // or throw an appropriate exception
}

private static void sendFile(DataOutputStream dos, Path file, String username) throws IOException {
    System.out.println("Preparing to send file: " + file);
    byte[] fileContent = Files.readAllBytes(file);
    dos.writeInt(fileContent.length);
    dos.write(fileContent);
    
    String baseFilename = file.getFileName().toString().replaceAll("\\.(cifrado|assinado|seguro)$", "");
    System.out.println("Base filename: " + baseFilename);
    
    if (file.toString().endsWith(".cifrado")) {
        Path keyFile = file.getParent().resolve(baseFilename + ".chave_secreta." + username);
        System.out.println("Looking for key file: " + keyFile);
        
        if (Files.exists(keyFile)) {
            System.out.println("Key file found. Sending key file...");
            byte[] keyContent = Files.readAllBytes(keyFile);
            dos.writeInt(keyContent.length);
            dos.write(keyContent);
        } else {
            System.out.println("Key file not found. Sending zero length.");
            dos.writeInt(0); // No key found, send 0 length
        }
    } else if (file.toString().endsWith(".assinado")) {
        Path signatureFile = file.getParent().resolve(baseFilename + ".assinatura.doctor");
        System.out.println("Looking for signature file: " + signatureFile);
        
        if (Files.exists(signatureFile)) {
            System.out.println("Signature file found. Sending signature...");
            byte[] signatureContent = Files.readAllBytes(signatureFile);
            dos.writeInt(signatureContent.length);
            dos.write(signatureContent);
        } else {
            System.out.println("Signature file not found. Sending zero length.");
            dos.writeInt(0); // No signature found, send 0 length
        }
    } else if (file.toString().endsWith(".seguro")) {
        System.out.println("Processing .seguro file...");

        Path keyFile = file.getParent().resolve(baseFilename + ".chave_secreta." + username);
        System.out.println("Looking for key file: " + keyFile);
        if (Files.exists(keyFile)) {
            System.out.println("Key file found. Sending key file...");
            byte[] keyContent = Files.readAllBytes(keyFile);
            dos.writeInt(keyContent.length);
            dos.write(keyContent);
        } else {
            System.out.println("Key file not found. Sending zero length.");
            dos.writeInt(0);
        }
        
        Path signatureFile = file.getParent().resolve(baseFilename + ".assinatura.doctor");
        System.out.println("Looking for signature file: " + signatureFile);
        if (Files.exists(signatureFile)) {
            System.out.println("Signature file found. Sending signature...");
            byte[] signatureContent = Files.readAllBytes(signatureFile);
            dos.writeInt(signatureContent.length);
            dos.write(signatureContent);
        } else {
            System.out.println("Signature file not found. Sending zero length.");
            dos.writeInt(0);
        }
    }
    System.out.println("File sending complete.");
}



}
