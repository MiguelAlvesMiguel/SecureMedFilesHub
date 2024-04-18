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

        Path patientDirectory = Paths.get(patientUsername);
        Files.createDirectories(patientDirectory);

        for (int i = 0; i < numberOfFiles; i++) {
            String cifradoFileName = dis.readUTF();
            int encryptedFileLength = dis.readInt();
            byte[] encryptedFileBytes = new byte[encryptedFileLength];
            dis.readFully(encryptedFileBytes);

            String seguroFileName = dis.readUTF();
            int secureFileLength = dis.readInt();
            byte[] secureFileBytes = new byte[secureFileLength];
            dis.readFully(secureFileBytes);

            String aesKeyFileName = dis.readUTF();
            int encryptedAesKeyLength = dis.readInt();
            byte[] encryptedAesKey = new byte[encryptedAesKeyLength];
            dis.readFully(encryptedAesKey);

            String assinadoFileName = dis.readUTF();
            int assinadoFileLength = dis.readInt();
            byte[] assinadoFileBytes = new byte[assinadoFileLength];
            dis.readFully(assinadoFileBytes);

            String assinaturaFileName = dis.readUTF();
            int signatureLength = dis.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);

            Path cifradoFilePath = patientDirectory.resolve(cifradoFileName);
            Path seguroFilePath = patientDirectory.resolve(seguroFileName);
            Path aesKeyPath = patientDirectory.resolve(aesKeyFileName);
            Path assinadoFilePath = patientDirectory.resolve(assinadoFileName);
            Path assinaturaFilePath = patientDirectory.resolve(assinaturaFileName);

            if (Files.exists(cifradoFilePath) || Files.exists(seguroFilePath) || Files.exists(aesKeyPath) ||
                    Files.exists(assinadoFilePath) || Files.exists(assinaturaFilePath)) {
                dos.writeUTF("Error: One or more files already exist on the server.");
            } else {
                Files.write(cifradoFilePath, encryptedFileBytes); // Save .cifrado file
                Files.write(seguroFilePath, secureFileBytes); // Save .seguro file
                Files.write(aesKeyPath, encryptedAesKey); // Save .chave_secreta.<patientUsername> file
                Files.write(assinadoFilePath, assinadoFileBytes); // Save .assinado file
                Files.write(assinaturaFilePath, signatureBytes); // Save .assinatura.<doctorUsername> file
                dos.writeUTF("Success: Files saved successfully.");
            }
            dos.flush(); // Ensure the client receives the response immediately
        }
    } catch (IOException e) {
        e.printStackTrace();
        dos.writeUTF("Error: An error occurred while processing the command."); // Notify client of failure
        dos.flush();
    }
}

private static KeyStore getKeyStore(String keystorePath, char[] password) {
    KeyStore keystore = null;
    try {
        keystore = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(keystorePath)) {
            keystore.load(is, password);
        }
        System.out.println("Keystore loaded successfully.");
    } catch (FileNotFoundException e) {
        System.err.println("Keystore file not found: " + e.getMessage());
    } catch (IOException e) {
        System.err.println("Failed to read keystore file: " + e.getMessage());
    } catch (NoSuchAlgorithmException e) {
        System.err.println("Algorithm to check the integrity of the keystore cannot be found: " + e.getMessage());
    } catch (CertificateException e) {
        System.err.println("Any of the certificates in the keystore could not be loaded: " + e.getMessage());
    } catch (KeyStoreException e) {
        System.err.println("Keystore was not initialized: " + e.getMessage());
    }

    if (keystore != null) {
        try {
            try {
                printKeystoreAliases(keystore);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } catch (Exception e) { // Catch any exception that occurs while printing the aliases
            System.err.println("Failed to print keystore aliases. Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    return keystore;
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

        if (Files.exists(cifradoFile) && Files.exists(keyFile)) {
            System.out.println("File Exists! Sending file... " + cifradoFile.getFileName());
            dos.writeBoolean(true); // File exists

            // Send the file name with the extension
            dos.writeUTF(requestedFilename + ".cifrado");

            // Read the encrypted file and key
            byte[] encryptedFileContent = Files.readAllBytes(cifradoFile);
            byte[] encryptedKeyContent = Files.readAllBytes(keyFile);

            // Send the encrypted file
            dos.writeInt(encryptedFileContent.length);
            dos.write(encryptedFileContent);

            // Send the encrypted key
            dos.writeInt(encryptedKeyContent.length);
            dos.write(encryptedKeyContent);
        } else {
            System.out.println("File does not exist: " + requestedFilename);
            dos.writeBoolean(false); // File does not exist
        }
        dos.flush();
    }

    dos.writeUTF("END");
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


