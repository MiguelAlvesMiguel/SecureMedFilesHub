package com.securehub.securemedfileshub;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
                System.out.println("Sending number of files: " + (numberOfFiles));
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
                    // The files are after args[4] in the -g command, so change the next loop to
                    // start from 4
                    idxOfFirstFile = 5;
                }
                for (int i = idxOfFirstFile; i < args.length; i++) {

                    Path file = Paths.get(args[i]);

                    if ("-g".equals(command)) {
                        processGCommand(dis, dos, patientUsername, doctorUsername, args);
                    } else {
                        if (!Files.exists(file)) {
                            System.err.println("File not found in the client: " + file);
                            continue;
                        }
                        if ("-sc".equals(command)) {
                            processScCommand(file, dos, doctorUsername,patientUsername);
                        } else if ("-sa".equals(command)) {
                            processSaCommand(file, dos, dis, doctorUsername,
                                    patientUsername);
                        } else if ("-se".equals(command)) {
                            processSeCommand(file, dos, dis,  doctorUsername,
                                    patientUsername);
                        } else {
                            System.err.println("Unknown command: " + command);
                            dos.writeUTF("Error: Unknown command");
                            continue;
                        }
                    }

                    // Here we read the server response for this particular file
                    String serverResponse = dis.readUTF();
                    System.out.println("Resposta server dps do processCommand: " + serverResponse); // Print the
                                                                                                    // server's response

                    if (serverResponse.startsWith("Error:"))
                        nOfFilesAlreadyPresent++;
                    else
                        nOfFilesSent++;

                }
                dos.flush();

                if (!"-g".equals(command)) {
                    try {
                        String serverResponse = dis.readUTF();
                        System.out.println("Resposta server dps do loop: " + serverResponse); // Print the server's
                                                                                              // response
                    } catch (EOFException e) {
                        System.out.println("All Done");
                    }
                    System.out.println("Operation complete. " + nOfFilesSent + " files sent, " + nOfFilesAlreadyPresent
                            + " files were already present.");
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

    }

    // Handle -sc command processing
    private static void processScCommand(Path file, DataOutputStream dos,  String doctorUsername,String patientUsername)
            throws Exception {
        KeyStore keystore = getKeyStore(patientUsername+".keystore", "patient".toCharArray());
        SecretKey aesKey = generateAESKey();
        byte[] encryptedFileBytes = encryptFile(Files.readAllBytes(file), aesKey);

        System.out.println("Fetching certificate with alias: " + doctorUsername + "cert");
        Certificate doctorCertificate = keystore.getCertificate(doctorUsername + "cert");
        System.out.println("Certificate retrieved Successfully");

        byte[] wrappedAesKey = wrapAESKey(aesKey, doctorCertificate);

        sendEncryptedFile(dos, file.getFileName().toString(), encryptedFileBytes, wrappedAesKey);
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
    private static void sendEncryptedFile(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
            byte[] encryptedAesKey) throws IOException {
        dos.writeUTF(filename); // Send base filename
        dos.writeInt(encryptedFileBytes.length); // Send encrypted file length
        dos.write(encryptedFileBytes); // Send encrypted file content

        dos.writeInt(encryptedAesKey.length); // Send encrypted AES key length right after file content
        dos.write(encryptedAesKey); // Send encrypted AES key content
    }

    // Client side: MySNS.java
    private static void processSaCommand(Path file, DataOutputStream dos, DataInputStream dis,  String doctorUsername, String patientUsername) throws Exception {
        
        KeyStore keystore = getKeyStore(doctorUsername+".keystore", "doctor".toCharArray());

        byte[] fileBytes = Files.readAllBytes(file);

        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", "doctor".toCharArray());

        byte[] signatureBytes = signFile(fileBytes, privateKey);

        sendSignedFile(dos, file.getFileName().toString(), fileBytes, signatureBytes, doctorUsername, patientUsername);

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
    private static void sendSignedFile(DataOutputStream dos, String fileName, byte[] fileBytes, byte[] signatureBytes,
            String doctorUsername, String patientUsername) throws IOException {
        // Send the signed file to the server
        dos.writeUTF(fileName + ".assinado");
        dos.writeInt(fileBytes.length);
        dos.write(fileBytes);

        // Send the signature to the server
        dos.writeUTF(fileName + ".assinatura." + doctorUsername);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);
    }

    private static void processSeCommand(Path file, DataOutputStream dos, DataInputStream dis, String doctorUsername, String patientUsername) throws Exception {
        KeyStore keystore = getKeyStore(doctorUsername + ".keystore", "doctor".toCharArray());
    
        SecretKey aesKey = generateAESKey();
    
        byte[] fileBytes = Files.readAllBytes(file);
        byte[] encryptedFileBytes = encryptFile(fileBytes, aesKey);
    
        Certificate patientCertificate = keystore.getCertificate(patientUsername + "cert");
        byte[] encryptedAesKey = encryptAESKey(aesKey, patientCertificate);
    
        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", "doctor".toCharArray());
        byte[] signatureBytes = signFile(fileBytes, privateKey);
    
        sendEncryptedAndSignedFiles(dos, file.getFileName().toString(), encryptedFileBytes, encryptedAesKey, fileBytes, signatureBytes, doctorUsername, patientUsername);
    
        dos.flush(); // Flush the DOS to send the file data immediately
    }
    
    private static void sendEncryptedAndSignedFiles(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
            byte[] encryptedAesKey, byte[] fileBytes, byte[] signatureBytes, String doctorUsername, String patientUsername)
            throws IOException {
        // Send encrypted file
        dos.writeUTF(filename + ".cifrado");
        dos.writeInt(encryptedFileBytes.length);
        dos.write(encryptedFileBytes);
    
        // Send secure file
        dos.writeUTF(filename + ".seguro");
        dos.writeInt(encryptedFileBytes.length);
        dos.write(encryptedFileBytes);
    
        // Send encrypted AES key
        dos.writeUTF(filename + ".chave_secreta." + patientUsername);
        dos.writeInt(encryptedAesKey.length);
        dos.write(encryptedAesKey);
        //Console log filename
        System.out.println("Filename: " + filename);

        dos.writeUTF(filename + ".assinado");
        dos.writeInt(fileBytes.length);
        dos.write(fileBytes);
    
        // n percebo pk é que não está a mandar este
        dos.writeUTF(filename + ".assinatura." + doctorUsername);
        dos.writeInt(signatureBytes.length);
        dos.write(signatureBytes);
    }
    // Handles the "-g" command: get files from the server
    private static void processGCommand(DataInputStream dis, DataOutputStream dos, 
            String patientUsername, String doctorUsername, String[] args) throws Exception {

        KeyStore keystore = getKeyStore(doctorUsername + ".keystore", "doctor".toCharArray());
        for (int i = 5; i < args.length; i++) {
            String filename = args[i];
            System.out.println("Requesting file: " + filename);
            dos.writeUTF(filename); // Send the filename with or without extension
            dos.flush(); // Make sure the request is sent

            boolean fileExists = dis.readBoolean();
            if (!fileExists) {
                System.err.println(filename + " does not exist on the server.");
                continue;
            }
            // Se chegámos aqui é porque o ficheiro existe
            // If it exists but doesn't end with a valid extension, we will request the full
            // name with the extension the server found
            if (!filename.endsWith(".cifrado") && !filename.endsWith(".assinado") && !filename.endsWith(".seguro")) {
                filename = dis.readUTF();
            }

            // Depending on the extension received, handle the file accordingly
            if (filename.endsWith(".cifrado")) {
                receiveEncryptedFileAndDecrypt(dis, filename, keystore, patientUsername);
            } else if (filename.endsWith(".assinado")) {
                receiveSignedFileAndVerify(dis, filename, keystore);
            } else if (filename.endsWith(".seguro")) {
                // receiveSecureFile(dis, filename, keystore, patientUsername);
            } else {
                System.err.println("Unknown file extension for: " + filename + " . Skipping file.");
            }
        }
    }

    private static void receiveSafestFile(DataInputStream dis, String baseFilename, KeyStore keystore,
            String patientUsername) throws Exception {
        // Implementation to handle the safest file form
        // This may involve a combination of decryption and signature verification
    }

    private static void receiveEncryptedFileAndDecrypt(DataInputStream dis, String filename, KeyStore keystore,
            String patientUsername) throws Exception {
        // Path to save decrypted files
        Path clientDirectory = Paths.get("Client");

        // Receive encrypted file content
        int encryptedFileLength = dis.readInt();
        byte[] encryptedFileContent = new byte[encryptedFileLength];
        dis.readFully(encryptedFileContent);
        System.out.println("Received encrypted file content for: " + filename);

        KeyStore clientKeystore = getKeyStore(patientUsername + ".keystore", "patient".toCharArray());

        // Receive encrypted AES key
        int encryptedKeyLength = dis.readInt();
        if (encryptedKeyLength > 0) {
            byte[] encryptedAesKey = new byte[encryptedKeyLength];
            dis.readFully(encryptedAesKey);
            System.out.println("Received encrypted AES key for: " + filename);

            // Decrypt the AES key using the RSA private key
            printKeystoreAliases(clientKeystore); // Call this method before retrieving the key to see all aliases in
                                                  // the keystore.
            PrivateKey rsaPrivateKey = (PrivateKey) clientKeystore.getKey("patientalias", "patient".toCharArray());
            if (rsaPrivateKey == null) {
                throw new Exception("PrivateKey not found for alias: " + patientUsername + "alias");
            }
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);

            // Use the decrypted AES key to decrypt the file content
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedFileContent = aesCipher.doFinal(encryptedFileContent);

            System.out.println("Decrypted file content for: " + filename);
            // Save the decrypted file content to a new file
            String decryptedFilename = filename.substring(0, filename.lastIndexOf(".cifrado")) + "_decrypted";
            Path decryptedFilePath = clientDirectory.resolve(decryptedFilename);
            Files.write(decryptedFilePath, decryptedFileContent);
            System.out.println("Decrypted file saved as: " + decryptedFilename);
        } else {
            System.err.println("No encrypted AES key received for: " + filename);
        }
    }

    private static void receiveSignedFileAndVerify(DataInputStream dis, String filename, KeyStore keystore)
            throws Exception {
        // Path to save signed files
        Path clientDirectory = Paths.get("Client");

        // Receive signed file content
        int signedFileLength = dis.readInt();
        byte[] signedFileContent = new byte[signedFileLength];
        dis.readFully(signedFileContent);
        System.out.println("Received signed file content for: " + filename);

        // Receive signature
        int signatureLength = dis.readInt();

        // If its 0 then it was not found
        if (signatureLength == 0) {
            System.err.println("No signature found for: " + filename);
            return;
        }

        byte[] signature = new byte[signatureLength];
        dis.readFully(signature);
        System.out.println("Received signature for: " + filename);

        // Verify signature
        KeyStore userKeystore = getKeyStore("patient.keystore", "patient".toCharArray());
        printKeystoreAliases(userKeystore);
        PublicKey publicKey = getPublicKeyFromKeystore(userKeystore, "doctorcert");

        if (verifySignature(signedFileContent, signature, publicKey)) {
            System.out.println("Signature verified successfully for: " + filename);

            // Save the signed file content to a new file
            String signedFilename = filename.substring(0, filename.lastIndexOf(".assinado")) + "_verified";
            Path signedFilePath = clientDirectory.resolve(signedFilename);
            Files.write(signedFilePath, signedFileContent);
            System.out.println("Verified signed file saved as: " + signedFilename);
        } else {
            System.err.println("Signature verification failed for: " + filename);
        }
    }

    private static void receiveSecureFile(DataInputStream dis, String filename, KeyStore keystore,
            String patientUsername) throws Exception {
        int fileLength = dis.readInt();
        byte[] encryptedFileContent = new byte[fileLength];
        dis.readFully(encryptedFileContent);

        int keyLength = dis.readInt();
        byte[] encryptedKeyContent = keyLength > 0 ? new byte[keyLength] : null;
        if (keyLength > 0) {
            dis.readFully(encryptedKeyContent);
        }

        int signatureLength = dis.readInt();
        byte[] signatureContent = signatureLength > 0 ? new byte[signatureLength] : null;
        if (signatureLength > 0) {
            dis.readFully(signatureContent);
        }

        // Decrypt the file content using the AES key
        PrivateKey privateKey = (PrivateKey) keystore.getKey(patientUsername + "alias", "patient".toCharArray());
        byte[] aesKeyBytes = decryptRSA(encryptedKeyContent, privateKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedFileContent = aesCipher.doFinal(encryptedFileContent);

        // Verify the signature using the public key
        PublicKey publicKey = keystore.getCertificate(patientUsername + "cert").getPublicKey();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(decryptedFileContent);
        boolean signatureVerified = signature.verify(signatureContent);

        // Save the decrypted and verified file content
        if (signatureVerified) { // VER ISTO AQUI QUE N SEI SE É ASSIM
            Path decryptedFilePath = Paths.get("Client", filename.replace(".seguro", "_verified.decrypted"));
            Files.write(decryptedFilePath, decryptedFileContent);
            System.out.println("Secure file decrypted and verified. Saved as: " + decryptedFilePath);
        } else {
            System.err.println("Signature verification failed for secure file: " + filename);
        }
    }

    // Decrypts the file using the provided AES key
    private static byte[] decryptFile(byte[] encryptedData, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(encryptedData);
    }

    private static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedData);
    }

    // Verifies the file's signature using the signer's public key
    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // Retrieves the AES key for a specific file from the keystore
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
