package finalll;

import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.util.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Server {
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_GREEN = "\u001B[32m"; // Green color for decrypted messages
    private static final String ANSI_CYAN = "\u001B[36m"; // Cyan color for encrypted messages
    private ArrayList<PrintWriter> clientOutputStreams;
    private ArrayList<String> onlineUsers = new ArrayList<>();
    AES aes;
    

    public class ClientHandler implements Runnable {
        private BufferedReader reader;
        private Socket sock;
        private PrintWriter client;

        public ClientHandler(Socket clientSocket, PrintWriter user) {
            client = user;
            try {
                sock = clientSocket;
                InputStreamReader isReader = new InputStreamReader(sock.getInputStream());
                reader = new BufferedReader(isReader);
            } catch (IOException ex) {
                System.out.println("Error beginning StreamReader.");
            }
        }

        public void run() {
            String encryptedMessage, connect = "Connect", disconnect = "Disconnect", chat = "Chat";
            String[] data;
            try {
                while ((encryptedMessage = reader.readLine()) != null) {
                    System.out.println(ANSI_CYAN + getTimestamp() + encryptedMessage + ANSI_RESET);
                    // decrypt 
                    String message = aes.decrypt(encryptedMessage);
                    String time = getTimestamp();
                    data = message.split("#");
                    System.out.println(ANSI_GREEN + time + data[0] + ": " + data[1] + ANSI_RESET);
                    if (data[2].equals(connect)) {
                        tellEveryone((data[0] + "# has connected." + "#" + chat));
                        userAdd(data[0]);
                    } else if (data[2].equals(disconnect)) {
                        System.out.println("Lost a connection");
                        tellEveryone((data[0] + "# has disconnected." + "#" + chat));
                        userRemove(data[0]);
                    } else if (data[2].equals(chat)) {
                        tellEveryone(message);
                    } else {
                        System.out.println("No Conditions were met.");
                    }
                }
            } catch (Exception ex) {
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new Server().go();
    }

    public void go() {
        aes = new AES();
        aes.initFromStrings("CHuO1Fjd8YgJqTyapibFBQ==", "e3IYYJC2hxe24/EO");
        clientOutputStreams = new ArrayList<>();
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("server.keystore"), "password".toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keyStore, "password".toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(8888);
            System.out.println("Server listening on port 8888");
            while (true) {
                SSLSocket clientSock = (SSLSocket) serverSocket.accept();
                PrintWriter writer = new PrintWriter(clientSock.getOutputStream());
                clientOutputStreams.add(writer);

                Thread listener = new Thread(new ClientHandler(clientSock, writer));
                listener.start();
                System.out.println("Got a connection.");
            }
        } catch (Exception ex) {
            System.out.println("Error making a connection.");
        }
    }

    public void userAdd(String name) {
        String message, add = "# #Connect", done = "Server# #Done";
        onlineUsers.add(name);
        String[] tempList = new String[onlineUsers.size()];
        onlineUsers.toArray(tempList);

        for (String token : tempList) {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }

    public void userRemove(String name) {
        String message, add = "# #Connect", done = "Server# #Done";
        onlineUsers.remove(name);
        String[] tempList = new String[onlineUsers.size()];
        onlineUsers.toArray(tempList);

        for (String token : tempList) {
            message = (token + add);
            tellEveryone(message);
        }
        tellEveryone(done);
    }
    
    private String getTimestamp() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        return "[" + formatter.format(now) + "]";
    }

    public void tellEveryone(String message) {
        Iterator<PrintWriter> it = clientOutputStreams.iterator();

        while (it.hasNext()) {
            try {
                PrintWriter writer = it.next();
                // encrypt
                String encryptedMessage = aes.encrypt(message);
                writer.println(encryptedMessage); // send encrypted message
                writer.flush();
            } catch (Exception ex) {
                System.out.println("Error telling everyone.");
            }
        }
    }
}
