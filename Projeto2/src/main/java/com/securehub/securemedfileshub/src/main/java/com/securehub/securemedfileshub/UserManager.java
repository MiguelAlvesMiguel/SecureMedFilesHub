package com.securehub.securemedfileshub;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.file.StandardCopyOption;

public class UserManager {
    private static final String USERS_FILE = "users";
    private static final String MAC_FILE = "users.mac";
    private Map<String, User> users;

    public UserManager() {
        users = new HashMap<>();
        loadUsers();
    }

    public void createUser(String username, String password, Path certificateFile) throws IOException {
        if (users.containsKey(username)) {
            throw new IllegalArgumentException("User already exists.");
        }

        String salt = generateSalt();
        String hashedPassword = hashPassword(password, salt);

        User user = new User(username, salt, hashedPassword);
        users.put(username, user);

        saveUser(user);
        saveCertificate(username, certificateFile);
    }

    public boolean authenticateUser(String username, String password) {
        User user = users.get(username);
        if (user != null) {
            String hashedPassword = hashPassword(password, user.getSalt());
            return hashedPassword.equals(user.getHashedPassword());
        }
        return false;
    }

    private void loadUsers() {
        Path usersFilePath = Paths.get(USERS_FILE);
        if (!Files.exists(usersFilePath)) {
            createAdminUser();
        }

        try {
            BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(";");
                if (parts.length == 3) {
                    String username = parts[0];
                    String salt = parts[1];
                    String hashedPassword = parts[2];
                    User user = new User(username, salt, hashedPassword);
                    users.put(username, user);
                }
            }
            reader.close();

            if (!verifyUsersMac()) {
                Scanner scanner = new Scanner(System.in);
                boolean macVerified = false;
                while (!macVerified) {
                    System.out.print("Enter the admin password: ");
                    String adminPassword = scanner.nextLine();

                    User adminUser = users.get("admin");
                    if (adminUser != null && authenticateUser("admin", adminPassword)) {
                        updateUsersMac(adminPassword);
                        macVerified = true;
                    } else {
                        System.out.println("MAC verification failed. Please try again.");
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Error loading users: " + e.getMessage());
        }
    }

    private void createAdminUser() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password for the 'admin' user: ");
        String adminPassword = scanner.nextLine();

        String salt = generateSalt();
        String hashedPassword = hashPassword(adminPassword, salt);

        User adminUser = new User("admin", salt, hashedPassword);
        users.put("admin", adminUser);

        try {
            saveUser(adminUser);
            updateUsersMac(adminPassword);
        } catch (IOException e) {
            throw new RuntimeException("Error saving admin user or updating MAC: " + e.getMessage());
        }
    }

    private void saveUser(User user) throws IOException {
        Path usersFilePath = Paths.get(USERS_FILE);
        if (!Files.exists(usersFilePath)) {
            Files.createFile(usersFilePath);
        }
        String userLine = user.toString() + System.lineSeparator();
        Files.write(usersFilePath, userLine.getBytes(), StandardOpenOption.APPEND);
    }

    private void saveCertificate(String username, Path certificateFile) throws IOException {
        Path certificateDir = Paths.get("certificates");
        Files.createDirectories(certificateDir);
        Path destinationFile = certificateDir.resolve(username + ".cer");
        Files.copy(certificateFile, destinationFile, StandardCopyOption.REPLACE_EXISTING);
    }

    private boolean verifyUsersMac() throws IOException {
        Path macFilePath = Paths.get(MAC_FILE);
        if (!Files.exists(macFilePath)) {
            return false;
        }
        String storedMac = new String(Files.readAllBytes(macFilePath)).trim();
        String currentMac = calculateUsersMac();
        return storedMac.equals(currentMac);
    }

    private void updateUsersMac(String adminPassword) throws IOException {
        User adminUser = users.get("admin");
        if (adminUser == null) {
            throw new RuntimeException("Admin user not found.");
        }

        String currentMac = calculateUsersMac();
        Files.write(Paths.get(MAC_FILE), currentMac.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private String calculateUsersMac() throws IOException {
        try {
            User adminUser = users.get("admin");
            if (adminUser == null) {
                throw new RuntimeException("Admin user not found.");
            }

            byte[] adminPasswordBytes = adminUser.getHashedPassword().getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] macKeyBytes = md.digest(adminPasswordBytes);
            SecretKeySpec macKey = new SecretKeySpec(macKeyBytes, "HmacSHA256");

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(macKey);
            byte[] usersBytes = Files.readAllBytes(Paths.get(USERS_FILE));
            byte[] macBytes = mac.doFinal(usersBytes);
            return Base64.getEncoder().encodeToString(macBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Error calculating users MAC: " + e.getMessage());
        }
    }

    private static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }

    private static String hashPassword(String password, String salt) {
        try {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedBytes = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hashedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error hashing password: " + e.getMessage());
        }
    }
}