package com.securehub.securemedfileshub;
import java.io.*;
import java.net.*;

public class MySNSServer {
    private static final int PORT = 12346; // Choose an appropriate port number

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server is listening on port " + PORT);

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("New client connected");

                // Handle client in a new thread
                new ClientHandler(socket).start();
            }

        } catch (IOException ex) {
            System.out.println("Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
}
