package com.securehub.securemedfileshub;

import javax.crypto.Cipher;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Enumeration;

public class MySNS {

    public static void main(String[] args) {
        try {
            /*
             * O cliente pode ser utilizado com as seguintes opções na linha de comandos:
             * [0] [1] [2] [3] [4] [5] [6] [7] ...
             * mySNS -a <serverAddress> -m <username do médico> -u <username do utente> -sc
             * {<filenames>}+
             * mySNS -a <serverAddress> -m <username do médico>-u <username do utente> -sa
             * {<filenames>}+
             * mySNS -a <serverAddress> -m <username do médico> -u <username do utente> -se
             * {<filenames>}+
             * mySNS -a <serverAddress> -u <username do utente> -g {<filenames>}
             * 
             */
            // Argument validation and setup...
            String serverAddress = args[1].split(":")[0];
            int serverPort = Integer.parseInt(args[1].split(":")[1]);
            String serverResponse = "";
            String command = "";
            String patientUsername = "";
            String doctorUsername = "";

            // Se for -g é diferente
            if (args[4].equals("-g")) {
                command = args[4];
                patientUsername = args[3];
            } else {
                command = args[6];
                doctorUsername = args[3];
                patientUsername = args[5];
            }

            int nOfFilesSent = 0;
            int nOfFilesAlreadyPresent = 0;
            int nOfFilesMissing = 0;
            int nOfFilesReceived = 0;

            try (Socket socket = new Socket(serverAddress, serverPort);
                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    DataInputStream dis = new DataInputStream(socket.getInputStream())) {
                dos.writeUTF(command); // Send the command

                // Process files based on the command
                int numberOfFiles = 0;

                if (command.equals("-g")) {
                    numberOfFiles = args.length - 5;
                } else {
                    numberOfFiles = args.length - 7;
                }
                System.out.println("Sending/receiving number of files: " + (numberOfFiles));
                // 1
                dos.writeInt(numberOfFiles); // Send the number of files to the server

                // Send the usernames before the main file loop:
                switch (command) {
                    case "-sc":
                        dos.writeUTF(patientUsername);
                        break;
                    case "-sa":
                        dos.writeUTF(patientUsername);
                        break;
                    case "-se":
                        dos.writeUTF(patientUsername);
                        break;
                    case "-g":
                        System.out.println("Sending patient username: " + patientUsername);
                        dos.writeUTF(patientUsername); // 2
                        break;
                    default:
                        System.err.println("Unknown command: " + command);
                        dos.writeUTF("Error: Unknown command");
                        break;
                }

                int idxOfFirstFile = 7;
                if ("-g".equals(command)) {
                    command = args[4];
                    patientUsername = args[3];
                    String[] filenames = new String[args.length - 5];
                    System.arraycopy(args, 5, filenames, 0, filenames.length);
                    if (filenames.length > 0) {
                        nOfFilesReceived=processGCommand(dis, dos, patientUsername, filenames);
                        System.out.println("Operation complete. Number of files received: " + nOfFilesReceived + ".");
                        dos.flush();
                    } else {
                        System.out.println("No files specified for the -g command.");
                    }

                } else {
                    for (int i = idxOfFirstFile; i < args.length; i++) {
                        System.out.println("Processing file: " + args[i]);
                        Path file = Paths.get(args[i]);

                        if (!Files.exists(file)) {
                            System.err.println("File not found in the client: " + file);
                            nOfFilesMissing++;
                            continue;
                        }
                        if ("-sc".equals(command)) {
                            processScCommand(file, dos, doctorUsername, patientUsername);
                        } else if ("-sa".equals(command)) {
                            processSaCommand(file, dos, dis, doctorUsername,
                                    patientUsername);
                        } else if ("-se".equals(command)) {
                            processSeCommand(file, dos, dis, doctorUsername,
                                    patientUsername);
                        } else {
                            System.err.println("Unknown command: " + command);
                            dos.writeUTF("Error: Unknown command");
                            continue;
                        }

                        // resolver bug
                        if (!"-g".equals(command)) {
                            serverResponse = dis.readUTF();
                            System.out.println("Resposta server dps do processCommand: " + serverResponse); // Print the
                        } // server's response

                        if (serverResponse.startsWith("Error:"))
                            nOfFilesAlreadyPresent++;
                        else
                            nOfFilesSent++;

                    }
                }

                if (!"-g".equals(command)) {
                    try {
                        serverResponse = dis.readUTF();
                        System.out.println("Resposta server dps do loop: " + serverResponse); // Print the server's
                                                                                              // response
                    } catch (EOFException e) {
                        System.out.println("All Done");
                    }
                    System.out.println("Operation complete. " + nOfFilesSent + " files sent, " + nOfFilesAlreadyPresent
                            + " files were already present, and " + nOfFilesMissing + " files were missing.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

    }

    private static int processGCommand(DataInputStream dis, DataOutputStream dos, String patientUsername,
            String[] filenames) throws IOException {

                int nOfFilesReceived = 0;
        for (String filename : filenames) {
            System.out.println("Requesting file: " + filename);
            dos.writeUTF(filename);
            dos.flush();

            boolean fileExists = dis.readBoolean();
            if (!fileExists) {
                System.out.println("File does not exist on the server: " + filename);
                continue;
            }
            System.out.println("File exists in some form: " + fileExists);
            while (fileExists) {
                String receivedFilename = dis.readUTF();
                System.out.println("Receiving file: " + receivedFilename);
                if (receivedFilename.endsWith(".cifrado")) {
                    receiveEncryptedFileAndDecrypt(dis, patientUsername, receivedFilename);
                    nOfFilesReceived++;
                } else if (receivedFilename.endsWith(".assinado")) {
                    receiveSignedFileAndVerify(dis, patientUsername, receivedFilename);nOfFilesReceived++;
                } else if (receivedFilename.endsWith(".seguro")) {
                    receiveSecureFile(dis, receivedFilename, patientUsername);nOfFilesReceived++;
                }
                fileExists = dis.readBoolean();
            }
        }

       return nOfFilesReceived;
    }

    // Handle -sc command processing
    private static void processScCommand(Path file, DataOutputStream dos, String doctorUsername, String patientUsername)
            throws Exception {
    	Scanner scanner = new Scanner(System.in);
    	
        KeyStore keystore = getKeyStore(doctorUsername + ".keystore", doctorUsername.toCharArray());
        SecretKey aesKey = generateAESKey();
        // byte[] encryptedFileBytes = encryptFile(Files.readAllBytes(file), aesKey);

        System.out.println("Fetching certificate with alias: " + patientUsername + "cert");
        Certificate patientCertificate = keystore.getCertificate(patientUsername + "cert");
        
        if (patientCertificate == null) {
            // Certificate not found in the keystore
            System.out.println("Certificate not found for alias: " + patientUsername + "cert");
            
            System.out.println("Do you want to export and import the certificate? (yes/no)");
            String choice = scanner.nextLine().trim().toLowerCase();

            if ("yes".equals(choice)) {
	            try {
	                KeyStore key = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());
	
	                FileInputStream fis = new FileInputStream(patientUsername + ".keystore");
	                key.load(fis, patientUsername.toCharArray());
	                fis.close();
	
	                // Export the certificate from the source keystore
	                Certificate patientCert = key.getCertificate(patientUsername + "alias");
	                if (patientCert == null) {
	                    throw new RuntimeException("Certificate not found in patient keystore.");
	                }
	
	                // Import the certificate into the current keystore
	                keystore.setCertificateEntry(patientUsername + "cert", patientCert);
	
	                // Save the updated keystore
	                FileOutputStream fos = new FileOutputStream(doctorUsername + ".keystore");
	                keystore.store(fos, doctorUsername.toCharArray());
	                fos.close();
	
	                System.out.println("Certificate imported into the keystore successfully.");
	            } catch (Exception e) {
	                e.printStackTrace();
	                // Handle exceptions appropriately
	            }
            } else if ("no".equals(choice)) {
            	return;
            	System.exit(1);
            	
	        } else {
	            // Handle the case where the user inputs an invalid choice
	            System.out.println("Invalid choice. Please enter 'yes' or 'no'.");
	            return;
	        }
            } else {
	            // Certificate retrieved successfully
	            System.out.println("Certificate retrieved successfully");
	            // Proceed with your logic here, e.g., encrypt file using the retrieved certificate
	            }
        patientCertificate = keystore.getCertificate(patientUsername + "cert");
        byte[] wrappedAesKey = wrapAESKey(aesKey, patientCertificate);

        sendEncryptedFile(dos, file.getFileName().toString(), file, wrappedAesKey);
    }

    // Generates an AES key
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // Encrypts file bytes with an AES key
    private static byte[] encryptFile(byte[] fileBytes, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return aesCipher.doFinal(fileBytes);
    }

    // Wraps the AES key with the public RSA key
    private static byte[] wrapAESKey(SecretKey aesKey, Certificate cert) throws Exception {
        if (cert == null) {
            System.err.println(
                    "Certificate is null. Check if the correct alias is used and the certificate exists in the KeyStore.");
            return null; // or throw an exception
        }

        PublicKey publicKey = cert.getPublicKey();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.WRAP_MODE, publicKey);
        return rsaCipher.wrap(aesKey);
    }

    // Encrypts the AES key with the public RSA key
    private static byte[] encryptAESKey(SecretKey aesKey, Certificate cert) throws Exception {
        if (cert == null) {
            System.err.println(
                    "Certificate is null. Check if the correct alias is used and the certificate exists in the KeyStore.");
            return null; // or throw an exception
        }
        PublicKey publicKey = cert.getPublicKey();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey.getEncoded());
    }

    // Sends encrypted file to the server
    private static void sendEncryptedFile(DataOutputStream dos, String filename, Path filePath, byte[] encryptedAesKey)
            throws IOException {
        dos.writeUTF(filename); // Send base filename
        long fileSize = Files.size(filePath);
        dos.writeLong(fileSize); // Send encrypted file length as long

        // Send encrypted file content in chunks
        byte[] buffer = new byte[4096];
        try (InputStream fileStream = Files.newInputStream(filePath)) {
            int bytesRead;
            while ((bytesRead = fileStream.read(buffer)) != -1) {
                dos.write(buffer, 0, bytesRead);
            }
        }

        dos.writeInt(encryptedAesKey.length); // Send encrypted AES key length right after file content
        dos.write(encryptedAesKey); // Send encrypted AES key content
    }

    // Client side: MySNS.java
    private static void processSaCommand(Path file, DataOutputStream dos, DataInputStream dis, String doctorUsername,
            String patientUsername) throws Exception {
    	
    	Scanner scanner = new Scanner(System.in);
    	
        KeyStore keystore = getKeyStore(doctorUsername + ".keystore", doctorUsername.toCharArray());

        byte[] fileBytes = Files.readAllBytes(file);

        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", doctorUsername.toCharArray());
        
        

        byte[] signatureBytes = signFile(fileBytes, privateKey);

        sendSignedFile(dos, file.getFileName().toString(), Files.newInputStream(file), fileBytes.length, signatureBytes,
                doctorUsername);

        dos.flush(); // Flush the DOS to send the file data immediately
    }

    // Signs the file using the patient's private key from the keystore
    private static byte[] signFile(byte[] fileBytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(fileBytes);
        return signature.sign();
    }

    // Sends the signed file and signature to the server
    private static void sendSignedFile(DataOutputStream dos, String fileName, InputStream fileStream, long fileSize,
            byte[] signatureBytes,
            String doctorUsername) throws IOException {
        // Send the signed file to the server
        dos.writeUTF(fileName + ".assinado");
        dos.writeLong(fileSize);
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fileStream.read(buffer)) != -1) {
            dos.write(buffer, 0, bytesRead);
        }

        // Send the signature to the server
        dos.writeUTF(fileName + ".assinatura." + doctorUsername);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);
    }

    private static void processSeCommand(Path file, DataOutputStream dos, DataInputStream dis, String doctorUsername,
            String patientUsername) throws Exception {
        System.out.println("Processing -se command...");

        Scanner scanner = new Scanner(System.in);
        KeyStore keystore = getKeyStore(doctorUsername + ".keystore", doctorUsername.toCharArray());

        SecretKey aesKey = generateAESKey();
        System.out.println("Generated AES key.");

        byte[] fileBytes = Files.readAllBytes(file);
        System.out.println("Read file bytes. Size: " + fileBytes.length);

        byte[] encryptedFileBytes = encryptFile(fileBytes, aesKey);
        System.out.println("Encrypted file bytes. Size: " + encryptedFileBytes.length);

        Certificate patientCertificate = keystore.getCertificate(patientUsername + "cert");
        
        
        if (patientCertificate == null) {
            // Certificate not found in the keystore
            System.out.println("Certificate not found for alias: " + patientUsername + "cert");
            
            System.out.println("Do you want to export and import the certificate? (yes/no)");
            String choice = scanner.nextLine().trim().toLowerCase();

            if ("yes".equals(choice)) {
	            try {
	                KeyStore key = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());
	
	                FileInputStream fis = new FileInputStream(patientUsername + ".keystore");
	                key.load(fis, patientUsername.toCharArray());
	                fis.close();
	
	                // Export the certificate from the source keystore
	                Certificate patientCert = key.getCertificate(patientUsername + "alias");
	                if (patientCert == null) {
	                    throw new RuntimeException("Certificate not found in patient keystore.");
	                }
	
	                // Import the certificate into the current keystore
	                keystore.setCertificateEntry(patientUsername + "cert", patientCert);
	
	                // Save the updated keystore
	                FileOutputStream fos = new FileOutputStream(doctorUsername + ".keystore");
	                keystore.store(fos, doctorUsername.toCharArray());
	                fos.close();
	
	                System.out.println("Certificate imported into the keystore successfully.");
	            } catch (Exception e) {
	                e.printStackTrace();
	                // Handle exceptions appropriately
	            }
            } else if ("no".equals(choice)) {
            	return;
            	System.exit(1);
            	
	        } else {
	            // Handle the case where the user inputs an invalid choice
	            System.out.println("Invalid choice. Please enter 'yes' or 'no'.");
	            return;
	        }
            } else {
	            // Certificate retrieved successfully
	            System.out.println("Certificate retrieved successfully");
	            // Proceed with your logic here, e.g., encrypt file using the retrieved certificate
	            }
        
        patientCertificate = keystore.getCertificate(patientUsername + "cert");
        
        byte[] encryptedAesKey = encryptAESKey(aesKey, patientCertificate);
        System.out.println("Encrypted AES key. Size: " + encryptedAesKey.length);

        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", doctorUsername.toCharArray());
        byte[] signatureBytes = signFile(fileBytes, privateKey);
        System.out.println("Signed file. Signature size: " + signatureBytes.length);

        System.out.println("Sending encrypted and signed files to the server...");
        sendEncryptedAndSignedFiles(dos, file.getFileName().toString(), encryptedFileBytes, fileBytes, encryptedAesKey,
                signatureBytes,
                doctorUsername, patientUsername);

        System.out.println("Waiting for server response...");
        String serverResponse = dis.readUTF();
        System.out.println("Server response: " + serverResponse);

        dos.flush(); // Flush the DOS to send the file data immediately
    }

    private static void sendEncryptedAndSignedFiles(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
            byte[] fileBytes, byte[] encryptedAesKey, byte[] signatureBytes, String doctorUsername,
            String patientUsername)
            throws IOException {
        // Send encrypted file
        System.out.println("Sending encrypted file: " + filename + ".cifrado");
        dos.writeUTF(filename + ".cifrado");
        dos.writeLong(encryptedFileBytes.length);
        sendFileChunk(dos, encryptedFileBytes);

        // Send secure file
        System.out.println("Sending secure file: " + filename + ".seguro");
        dos.writeUTF(filename + ".seguro");
        dos.writeLong(encryptedFileBytes.length);
        sendFileChunk(dos, encryptedFileBytes);

        // Send encrypted AES key
        System.out.println("Sending encrypted AES key: " + filename + ".chave_secreta." + patientUsername);
        dos.writeUTF(filename + ".chave_secreta." + patientUsername);
        dos.writeInt(encryptedAesKey.length);
        dos.write(encryptedAesKey);

        // Console log filename
        System.out.println("Filename: " + filename);

        System.out.println("Sending signed file: " + filename + ".assinado");
        dos.writeUTF(filename + ".assinado");
        dos.writeLong(fileBytes.length);
        sendFileChunk(dos, fileBytes);

        System.out.println("Sending signature: " + filename + ".assinatura." + doctorUsername);
        dos.writeUTF(filename + ".assinatura." + doctorUsername);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);
    }

    private static void sendFileChunk(DataOutputStream dos, byte[] fileBytes) throws IOException {
        int offset = 0;
        int length = 4096;
        while (offset < fileBytes.length) {
            if (offset + length > fileBytes.length) {
                length = fileBytes.length - offset;
            }
            dos.write(fileBytes, offset, length);
            offset += length;
        }
        System.out.println("File chunk sent.");
    }

    private static void receiveSignedFileAndVerify(DataInputStream dis, String patientUsername, String receivedFilename)
            throws IOException {
        try {
            KeyStore keystore = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

            long signedFileLength = dis.readLong();
            Path tempFile = Files.createTempFile("signed", ".tmp");
            try (OutputStream tempOut = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[4096];
                long bytesRead = 0;
                while (bytesRead < signedFileLength) {
                    int bytesToRead = (int) Math.min(buffer.length, signedFileLength - bytesRead);
                    int bytesReceived = dis.read(buffer, 0, bytesToRead);
                    if (bytesReceived == -1) {
                        throw new EOFException("Unexpected end of stream while reading signed file");
                    }
                    tempOut.write(buffer, 0, bytesReceived);
                    bytesRead += bytesReceived;
                }
            }

            // Extract the doctor's username from the signature filename
            String signatureFileName = dis.readUTF();
            System.out.println("Signature filename: " + signatureFileName);
            String doctorUsername = signatureFileName.substring(signatureFileName.lastIndexOf(".") + 1);
            System.out.println("Doctor username: " + doctorUsername);

            int signatureLength = dis.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);

            // Retrieve the doctor's certificate from the keystore
            PublicKey publicKey = keystore.getCertificate(doctorUsername + "cert").getPublicKey();

            // Verify the signature
            boolean signatureValid = verifySignature(Files.readAllBytes(tempFile), signatureBytes, publicKey);

            if (signatureValid) {
                // Save the signed file
                String outputFilename = receivedFilename.replace(".assinado", "");
                Path outputFilePath = Paths.get("Client", patientUsername, "Assinados", outputFilename);
                Files.createDirectories(outputFilePath.getParent());
                Files.move(tempFile, outputFilePath, StandardCopyOption.REPLACE_EXISTING);
                System.out.println("File downloaded and signature verified: " + outputFilename);
            } else {
                System.out.println("Signature verification failed for file: " + receivedFilename);
                Files.delete(tempFile);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error occurred while verifying the signature of file: " + receivedFilename);
        }
    }

    private static void receiveSecureFile(DataInputStream dis, String receivedFilename, String patientUsername)
            throws IOException {
        try {
            KeyStore keystore = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

            long encryptedFileLength = dis.readLong();
            Path tempFile = Files.createTempFile("secure", ".tmp");
            try (OutputStream tempOut = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[4096];
                long bytesRead = 0;
                while (bytesRead < encryptedFileLength) {
                    int bytesToRead = (int) Math.min(buffer.length, encryptedFileLength - bytesRead);
                    int bytesReceived = dis.read(buffer, 0, bytesToRead);
                    if (bytesReceived == -1) {
                        throw new EOFException("Unexpected end of stream while reading secure file");
                    }
                    tempOut.write(buffer, 0, bytesReceived);
                    bytesRead += bytesReceived;
                }
            }

            int encryptedKeyLength = dis.readInt();
            byte[] encryptedKeyContent = new byte[encryptedKeyLength];
            dis.readFully(encryptedKeyContent);

            // Extract the doctor's username from the signature filename
            String signatureFileName = dis.readUTF();
            System.out.println("Signature filename: " + signatureFileName);
            String doctorUsername = signatureFileName.substring(signatureFileName.lastIndexOf(".") + 1);
            System.out.println("Doctor username: " + doctorUsername);

            int signatureLength = dis.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dis.readFully(signatureBytes);

            // Decrypt the AES key
            PrivateKey privateKey = (PrivateKey) keystore.getKey(patientUsername + "alias",
                    patientUsername.toCharArray());
            byte[] decryptedKeyBytes = decryptAESKey(encryptedKeyContent, privateKey);
            SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, "AES");

            // Decrypt the file
            byte[] encryptedFileBytes = Files.readAllBytes(tempFile);
            byte[] decryptedFileContent = decryptFile(encryptedFileBytes, decryptedKey);

            // Retrieve the doctor's certificate from the keystore
            PublicKey publicKey = keystore.getCertificate(doctorUsername + "cert").getPublicKey();

            // Verify the signature
            boolean signatureValid = verifySignature(decryptedFileContent, signatureBytes, publicKey);

            if (signatureValid) {
                // Save the decrypted and verified file
                String outputFilename = receivedFilename.replace(".seguro", "");
                Path outputFilePath = Paths.get("Client", patientUsername, "Seguros", outputFilename);
                Files.createDirectories(outputFilePath.getParent());
                Files.write(outputFilePath, decryptedFileContent, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                System.out.println("Secure file downloaded, decrypted, and verified: " + outputFilename);
            } else {
                System.out.println("Signature verification failed for secure file: " + receivedFilename);
            }
            Files.delete(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error occurred while processing secure file: " + receivedFilename);
        }
    }

    private static boolean verifySignature(byte[] fileContent, byte[] signatureBytes, PublicKey publicKey)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(fileContent);
        return signature.verify(signatureBytes);
    }

    private static void receiveEncryptedFileAndDecrypt(DataInputStream dis, String patientUsername,
            String receivedFilename) throws IOException {
        try {
            KeyStore keystore = getKeyStore(patientUsername + ".keystore", patientUsername.toCharArray());

            long encryptedFileLength = dis.readLong();
            Path tempFile = Files.createTempFile("encrypted", ".tmp");
            try (OutputStream tempOut = Files.newOutputStream(tempFile)) {
                byte[] buffer = new byte[4096];
                long bytesRead = 0;
                while (bytesRead < encryptedFileLength) {
                    int bytesToRead = (int) Math.min(buffer.length, encryptedFileLength - bytesRead);
                    int bytesReceived = dis.read(buffer, 0, bytesToRead);
                    if (bytesReceived == -1) {
                        throw new EOFException("Unexpected end of stream while reading encrypted file");
                    }
                    tempOut.write(buffer, 0, bytesReceived);
                    bytesRead += bytesReceived;
                }
            }

            int encryptedKeyLength = dis.readInt();
            byte[] encryptedKeyContent = new byte[encryptedKeyLength];
            dis.readFully(encryptedKeyContent);

            // Decrypt the AES key
            PrivateKey privateKey = (PrivateKey) keystore.getKey(patientUsername + "alias",
                    patientUsername.toCharArray());
            System.out.println("Private key: " + privateKey);
            byte[] decryptedKeyBytes = decryptAESKey(encryptedKeyContent, privateKey);
            SecretKey decryptedKey = new SecretKeySpec(decryptedKeyBytes, "AES");

            // Decrypt the file
            byte[] encryptedFileBytes = Files.readAllBytes(tempFile);
            byte[] decryptedFileContent = decryptFile(encryptedFileBytes, decryptedKey);

            // Save the decrypted file
            String outputFilename = receivedFilename.replace(".cifrado", "");
            Path outputFilePath = Paths.get("Client", patientUsername, "Cifrados", outputFilename);
            Files.createDirectories(outputFilePath.getParent());
            Files.write(outputFilePath, decryptedFileContent, StandardOpenOption.CREATE, StandardOpenOption.WRITE);

            System.out.println("File downloaded and decrypted: " + outputFilename);
            Files.delete(tempFile);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error occurred while decrypting the file: " + receivedFilename);
        }
    }

    private static byte[] decryptAESKey(byte[] encryptedKeyBytes, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedKeyBytes);
    }

    private static byte[] decryptFile(byte[] encryptedFileBytes, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        return aesCipher.doFinal(encryptedFileBytes);
    }

    // Retrieves the AES key for a specific file from the keystore
    private static KeyStore getKeyStore(String keystorePath, char[] password) {
        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("JKS");
            try (InputStream is = new FileInputStream(keystorePath)) {
                keystore.load(is, password);
            }
            // System.out.println("Keystore loaded successfully.");
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

        // if (keystore != null) {
        // try {
        // try {
        // printKeystoreAliases(keystore);
        // } catch (Exception e) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
        // } catch (Exception e) { // Catch any exception that occurs while printing the
        // aliases
        // System.err.println("Failed to print keystore aliases. Error: " +
        // e.getMessage());
        // e.printStackTrace();
        // }
        // }

        return keystore;
    }

    private static SecretKey getAESKeyFromKeystore(KeyStore keystore, String alias, char[] password) {
        try {
            System.out.println("Keystore type: " + keystore.getType());
            System.out.println(
                    "Trying to get key from keystore: " + alias + " with password: " + String.valueOf(password));
            Key key = keystore.getKey(alias, password);
            if (key != null) {
                System.out.println("Key algorithm: " + key.getAlgorithm());
                if (key instanceof SecretKey) {
                    return new SecretKeySpec(key.getEncoded(), "AES");
                } else {
                    System.err.println("Retrieved key is not a SecretKey: " + key.getClass().getName());
                }
            } else {
                System.err.println("No key found in the keystore for the alias: " + alias);
            }
        } catch (Exception e) {
            System.err.println("Failed to get key from keystore. Error: " + e.getMessage());
            e.printStackTrace();
            try {
                printKeystoreAliases(keystore);
            } catch (Exception ex) {
                System.err.println("Failed to print keystore aliases. Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        return null;
    }

    // Retrieves the public key for verifying the signature from the keystore
    private static PublicKey getPublicKeyFromKeystore(KeyStore keystore, String alias) throws Exception {
        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }

    private static void printKeystoreAliases(KeyStore keystore) throws Exception {
        System.out.println("Keystore contains the following aliases:");
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias in keystore: " + alias);
        }
    }

}
