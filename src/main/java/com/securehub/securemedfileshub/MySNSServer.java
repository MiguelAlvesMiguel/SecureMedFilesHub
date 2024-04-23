package com.securehub.securemedfileshub;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
            //send end response to client

            dos.writeUTF("END");
        
        } catch (Exception e) {
            System.err.println("Error processing client request: " + e.getMessage());
            e.printStackTrace();
            dos.writeUTF("Error: " + e.getMessage());
            dos.flush();
        } finally {
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
        long fileSize = dis.readLong();
        Path filePath = patientDirectory.resolve(filename + ".cifrado");
        try (OutputStream fileOut = Files.newOutputStream(filePath)) {
            byte[] buffer = new byte[4096];
            long bytesRead = 0;
            while (bytesRead < fileSize) {
                int bytesToRead = (int) Math.min(buffer.length, fileSize - bytesRead);
                int bytesReceived = dis.read(buffer, 0, bytesToRead);
                if (bytesReceived == -1) {
                    throw new EOFException("Unexpected end of stream while reading encrypted file");
                }
                fileOut.write(buffer, 0, bytesReceived);
                bytesRead += bytesReceived;
            }
        }

        int keyLength = dis.readInt();
        byte[] keyContent = new byte[keyLength];
        dis.readFully(keyContent);

        Path keyPath = patientDirectory.resolve(filename + ".chave_secreta." + patientUsername);

        if (Files.exists(keyPath)) {
            dos.writeUTF("Error: File " + filename + ".cifrado or its key already exists on the server.");
        } else {
            Files.write(keyPath, keyContent);
            dos.writeUTF("Success: File " + filename + ".cifrado and its key saved successfully.");
        }
    }
    dos.writeUTF("END");
    dos.flush();
}

private static void handleSaCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    int numberOfFiles = dis.readInt();
    String patientUsername = dis.readUTF();

    Path patientDirectory = Paths.get(patientUsername);
    Files.createDirectories(patientDirectory);

    for (int i = 0; i < numberOfFiles; i++) {
        String signedFileName = dis.readUTF();
        long signedFileSize = dis.readLong();
        Path signedFilePath = patientDirectory.resolve(signedFileName);
        try (OutputStream fileOut = Files.newOutputStream(signedFilePath)) {
            byte[] buffer = new byte[4096];
            long bytesRead = 0;
            while (bytesRead < signedFileSize) {
                int bytesToRead = (int) Math.min(buffer.length, signedFileSize - bytesRead);
                int bytesReceived = dis.read(buffer, 0, bytesToRead);
                if (bytesReceived == -1) {
                    throw new EOFException("Unexpected end of stream while reading signed file");
                }
                fileOut.write(buffer, 0, bytesReceived);
                bytesRead += bytesReceived;
            }
        }

        String signatureFileName = dis.readUTF();
        int signatureLength = dis.readInt();
        byte[] signatureContent = new byte[signatureLength];
        dis.readFully(signatureContent);

        Path signatureFilePath = patientDirectory.resolve(signatureFileName);

        if (Files.exists(signatureFilePath)) {
            dos.writeUTF("Error: File " + signedFileName + " or its signature already exists on the server.");
        } else {
            Files.write(signatureFilePath, signatureContent);
            dos.writeUTF("Success: File " + signedFileName + " and its signature saved successfully.");
        }
        dos.flush();
    }
    dos.writeUTF("END");
}

private static void handleSeCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    try {
        int numberOfFiles = dis.readInt();
        System.out.println("Received number of files: " + numberOfFiles);
        
        String patientUsername = dis.readUTF();
        System.out.println("Received patient username: " + patientUsername);

        Path patientDirectory = Paths.get(patientUsername);
        Files.createDirectories(patientDirectory);

        boolean allFilesSaved = true;

        for (int i = 0; i < numberOfFiles; i++) {

            String cifradoFileName = dis.readUTF();
            System.out.println("Received cifrado file name: " + cifradoFileName);
            long encryptedFileSize = dis.readLong();
            System.out.println("Received encrypted file size: " + encryptedFileSize);
            Path cifradoFilePath = patientDirectory.resolve(cifradoFileName);

            // Receive cifrado file chunk
            try (OutputStream cifradoOut = Files.newOutputStream(cifradoFilePath)) {
                receiveFileChunk(dis, cifradoOut, encryptedFileSize);
            }
            System.out.println("Cifrado file chunk received and saved.");

            String seguroFileName = dis.readUTF();
            System.out.println("Received seguro file name: " + seguroFileName);
            long secureFileSize = dis.readLong();
            System.out.println("Received secure file size: " + secureFileSize);
            Path seguroFilePath = patientDirectory.resolve(seguroFileName);

            // Receive seguro file chunk
            try (OutputStream seguroOut = Files.newOutputStream(seguroFilePath)) {
                receiveFileChunk(dis, seguroOut, secureFileSize);
            }
            System.out.println("Seguro file chunk received and saved.");

            String aesKeyFileName = dis.readUTF();
            System.out.println("Received AES key file name: " + aesKeyFileName);
            int encryptedAesKeyLength = dis.readInt();
            System.out.println("Received encrypted AES key length: " + encryptedAesKeyLength);
            byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
            dis.readFully(encryptedAesKey);
            Path aesKeyPath = patientDirectory.resolve(aesKeyFileName);

            String assinadoFileName = dis.readUTF();
            System.out.println("Received assinado file name: " + assinadoFileName);
            long assinadoFileSize = dis.readLong();
            System.out.println("Received assinado file size: " + assinadoFileSize);
            Path assinadoFilePath = patientDirectory.resolve(assinadoFileName);

            // Receive assinado file chunk
            try (OutputStream assinadoOut = Files.newOutputStream(assinadoFilePath)) {
                receiveFileChunk(dis, assinadoOut, assinadoFileSize);
            }
            System.out.println("Assinado file chunk received and saved.");

            String assinaturaFileName = dis.readUTF();
            System.out.println("Received assinatura file name: " + assinaturaFileName);
            int signatureLength = dis.readInt();
            System.out.println("Received signature length: " + signatureLength);
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);
            Path assinaturaFilePath = patientDirectory.resolve(assinaturaFileName);
                // Save the keys
                System.out.println("Saving AES key...");
                Files.write(aesKeyPath, encryptedAesKey);
                System.out.println("AES key saved.");

                System.out.println("Saving signature...");
                Files.write(assinaturaFilePath, signatureBytes);
                System.out.println("Signature saved.");

            //Send success response to the client
            dos.writeUTF("Success: File saved successfully.");
            System.out.println("Success response sent to the client.");
            dos.writeUTF("next file if exists...");
            System.out.println("next file if exists... sent to the client.");
            
        }

        //Check if all files were saved successfully

        if (allFilesSaved) {
            System.out.println("Sending success response to the client.");
            dos.writeUTF("Success: Files saved successfully.");
        } else {
            System.out.println("Sending partial success response to the client.");
            dos.writeUTF("Partial Success: Some files were saved, but others already existed.");
        }
        dos.flush();

    } catch (IOException e) {
        e.printStackTrace();
        System.out.println("Sending error response to the client.");
        dos.writeUTF("Error: An error occurred while processing the command.");
        dos.flush();
    }
}

private static void receiveFileChunk(DataInputStream dis, OutputStream out, long fileSize) throws IOException {
    byte[] buffer = new byte[4096];
    long bytesRead = 0;
    while (bytesRead < fileSize) {
        int bytesToRead = (int) Math.min(buffer.length, fileSize - bytesRead);
        int bytesReceived = dis.read(buffer, 0, bytesToRead);
        if (bytesReceived == -1) {
            throw new EOFException("Unexpected end of stream while reading file chunk");
        }
        out.write(buffer, 0, bytesReceived);
        bytesRead += bytesReceived;
    }
}

private static void handleGCommand(DataInputStream dis, DataOutputStream dos) throws IOException {
    int numberOfFiles = dis.readInt();
    String patientUsername = dis.readUTF();

    Path patientDirectory = Paths.get(patientUsername);

    for (int i = 0; i < numberOfFiles; i++) {
        System.out.println("Requesting file " + (i + 1) + " of " + numberOfFiles);
        
        String requestedFilename = dis.readUTF();
        System.out.println("Requested file: " + requestedFilename);


        Path cifradoFile = patientDirectory.resolve(requestedFilename + ".cifrado");
        Path keyFile = patientDirectory.resolve(requestedFilename + ".chave_secreta." + patientUsername);
        Path assinadoFile = patientDirectory.resolve(requestedFilename + ".assinado");

        // Search for the signature file with the doctor's username
        Path signatureFile = null;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(patientDirectory, requestedFilename + ".assinatura.*")) {
            for (Path file : stream) {
                signatureFile = file;
                break;
            }
        } catch (IOException e) {
            System.err.println("Error searching for signature file: " + e.getMessage());
        }

        System.out.println("Signature file: " + (signatureFile != null ? signatureFile.getFileName() : "null"));

        Path seguroFile = patientDirectory.resolve(requestedFilename + ".seguro");

        boolean fileExists = (Files.exists(cifradoFile) && Files.exists(keyFile)) ||
                (Files.exists(assinadoFile) && signatureFile != null) ||
                Files.exists(seguroFile);

        if (!fileExists)
            {
                dos.writeBoolean(false);
                continue;
            }
      

        if (Files.exists(cifradoFile) && Files.exists(keyFile)) {
            System.out.println("Cifrado file exists! Sending file... " + cifradoFile.getFileName());
            dos.writeBoolean(true);
            dos.writeUTF(requestedFilename + ".cifrado");

            // Read and send the encrypted file in chunks
            long encryptedFileSize = Files.size(cifradoFile);
            dos.writeLong(encryptedFileSize);
            try (InputStream fileStream = Files.newInputStream(cifradoFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fileStream.read(buffer)) != -1) {
                    dos.write(buffer, 0, bytesRead);
                }
            }

            byte[] encryptedKeyContent = Files.readAllBytes(keyFile);
            dos.writeInt(encryptedKeyContent.length);
            dos.write(encryptedKeyContent);
        }

        if (Files.exists(assinadoFile) && signatureFile != null) {
            System.out.println("Signed file exists! Sending file... " + assinadoFile.getFileName());
            dos.writeBoolean(true);
            dos.writeUTF(requestedFilename + ".assinado");

            // Read and send the signed file in chunks
            long signedFileSize = Files.size(assinadoFile);
            dos.writeLong(signedFileSize);
            try (InputStream fileStream = Files.newInputStream(assinadoFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fileStream.read(buffer)) != -1) {
                    dos.write(buffer, 0, bytesRead);
                }
            }

            dos.writeUTF(signatureFile.getFileName().toString());
            byte[] signatureBytes = Files.readAllBytes(signatureFile);
            dos.writeInt(signatureBytes.length);
            dos.write(signatureBytes);
        }

        if (Files.exists(seguroFile)) {
            System.out.println("Secure file exists! Sending file... " + seguroFile.getFileName());
            dos.writeBoolean(true);
            dos.writeUTF(requestedFilename + ".seguro");
           
            // Read and send the secure file in chunks
            long secureFileSize = Files.size(seguroFile);
            dos.writeLong(secureFileSize);
            try (InputStream fileStream = Files.newInputStream(seguroFile)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fileStream.read(buffer)) != -1) {
                    dos.write(buffer, 0, bytesRead);
                }
            }

            byte[] encryptedKeyContent = Files.readAllBytes(keyFile);
            dos.writeInt(encryptedKeyContent.length);
            dos.write(encryptedKeyContent);

            if (signatureFile != null) {
                dos.writeUTF(signatureFile.getFileName().toString());
                byte[] signatureBytes = Files.readAllBytes(signatureFile);
                dos.writeInt(signatureBytes.length);
                dos.write(signatureBytes);
            } else {
                dos.writeInt(0);
            }
        }

        //Para sair do loop no client
        dos.writeBoolean(false);
        dos.flush();
    }

    dos.flush();
}

//Helper
private static void printKeystoreAliases(KeyStore keystore) throws Exception {
    System.out.println("Keystore contains the following aliases:");
    Enumeration<String> aliases = keystore.aliases();
    while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        System.out.println("Alias in keystore: " + alias);
    }
}
}


