package finalll;

import java.awt.Cursor;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.util.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class Client extends javax.swing.JFrame {
    private String username;
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private ArrayList<String> userList = new ArrayList<>();
    private boolean isConnected = false;
    AES aes;

    public Client() {
        initComponents();
        aes = new AES();
        aes.initFromStrings("CHuO1Fjd8YgJqTyapibFBQ==", "e3IYYJC2hxe24/EO");
        
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (isConnected) {
                    disconnectButtonActionPerformed(null); // Call disconnectButtonActionPerformed method
                }
            }
        });
    }
    
    public void userAdd(String string) {
        userList.add(string);
    }

    public void userRemove(String string) {
        userList.remove(string);
    }

    public class IncomingReader implements Runnable {
        public void run() {
            String encryptedStream;
            String[] data;
            String done = "Done", connect = "Connect", disconnect = "Disconnect", chat = "Chat";
            
            try {
                while ((encryptedStream = reader.readLine()) != null) {
                    // decrypt
                    String stream = aes.decrypt(encryptedStream);
                    data = stream.split("#");
                    if (data[2].equals(chat)) {
                        chatArea.append(data[0] + ": "  + data[1] + "\n");
                    } else if (data[2].equals(connect)) {
//                        chatArea.removeAll();
                        userAdd(data[0]);
                    } else if (data[2].equals(disconnect)) {
                        userRemove(data[0]);
                    } else if (data[2].equals(done)) {
                        usersList.setText("");
                        writeUsers();
                        userList.clear();
                    }
                }
            } catch (Exception ex) {
                // Handle exceptions
            }
        }

        private void writeUsers() {
            String[] tempList = new String[userList.size()];
            userList.toArray(tempList);
            for (String token:tempList) {
                usersList.append(token + "\n");
            }
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        usernameLabel = new javax.swing.JLabel();
        usernameField = new javax.swing.JTextField();
        connectButton = new javax.swing.JButton();
        disconnectButton = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        chatArea = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        inputArea = new javax.swing.JTextArea();
        sendButton = new javax.swing.JButton();
        activeUsersLabel = new javax.swing.JLabel();
        jScrollPane3 = new javax.swing.JScrollPane();
        usersList = new javax.swing.JTextArea();

        setTitle("Encrypted Exchange");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        usernameLabel.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        usernameLabel.setText("Username");

        usernameField.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        usernameField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                usernameFieldActionPerformed(evt);
            }
        });

        connectButton.setBackground(new java.awt.Color(0, 141, 218));
        connectButton.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        connectButton.setForeground(new java.awt.Color(239, 239, 239));
        connectButton.setText("Connect");
        connectButton.setToolTipText("Connect to the server");
        connectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                connectButtonActionPerformed(evt);
            }
        });
        connectButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        disconnectButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        disconnectButton.setBackground(new java.awt.Color(65, 201, 226));
        disconnectButton.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        disconnectButton.setForeground(new java.awt.Color(239, 239, 239));
        disconnectButton.setText("Disconnect");
        disconnectButton.setToolTipText("Disconnect from the server");
        disconnectButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                disconnectButtonActionPerformed(evt);
            }
        });

        chatArea.setEditable(false);
        chatArea.setBackground(new java.awt.Color(216, 239, 244));
        chatArea.setColumns(20);
        chatArea.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        chatArea.setLineWrap(true);
        chatArea.setRows(5);
        jScrollPane1.setViewportView(chatArea);

        inputArea.setColumns(20);
        inputArea.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        inputArea.setRows(5);
        jScrollPane2.setViewportView(inputArea);

        sendButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        sendButton.setBackground(new java.awt.Color(0, 141, 218));
        sendButton.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        sendButton.setForeground(new java.awt.Color(239, 239, 239));
        sendButton.setText("Send");
        sendButton.setToolTipText("Send message");
        sendButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendButtonActionPerformed(evt);
            }
        });

        activeUsersLabel.setBackground(new java.awt.Color(102, 255, 102));
        activeUsersLabel.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        activeUsersLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        activeUsersLabel.setText("Online Members");

        usersList.setEditable(false);
        usersList.setBackground(new java.awt.Color(255, 255, 255));
        usersList.setColumns(20);
        usersList.setFont(new java.awt.Font("Century Gothic", 0, 12)); // NOI18N
        usersList.setLineWrap(true);
        usersList.setRows(5);
        jScrollPane3.setViewportView(usersList);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 350, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(sendButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(usernameLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(usernameField, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(connectButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(disconnectButton)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .addComponent(activeUsersLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 131, Short.MAX_VALUE))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(usernameLabel)
                    .addComponent(usernameField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(connectButton)
                    .addComponent(disconnectButton)
                    .addComponent(activeUsersLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 317, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(sendButton, javax.swing.GroupLayout.DEFAULT_SIZE, 59, Short.MAX_VALUE)))
                    .addComponent(jScrollPane3))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void usernameFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_usernameFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_usernameFieldActionPerformed

    private void connectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_connectButtonActionPerformed
        if (!isConnected) {
            username = usernameField.getText();
            usernameField.setEditable(false);
            try {
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(new FileInputStream("client.truststore"), "password".toCharArray());

                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                trustManagerFactory.init(trustStore);

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

                SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
                socket = (SSLSocket) sslSocketFactory.createSocket("localhost", 8888);

                InputStreamReader sreader = new InputStreamReader(socket.getInputStream());
                reader = new BufferedReader(sreader);
                writer = new PrintWriter(socket.getOutputStream());
                // encrypt
                String encryptedMessage = aes.encrypt(username + "#has connected.#Connect");
                writer.println(encryptedMessage);
                writer.flush();
                isConnected = true;
            } catch (Exception ex) {
                chatArea.append("Can't Connect! Try Again.\n");
                usernameField.setEditable(true);
            }
            ListenThread();
        } else {
            chatArea.append("You are already connected. \n");
        }
    }//GEN-LAST:event_connectButtonActionPerformed

    private void disconnectButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_disconnectButtonActionPerformed
        try {
            // encrypt
            String encryptedMessage = aes.encrypt(username + "#has disconnected.#Disconnect");
            writer.println(encryptedMessage);
            writer.flush();
        } catch (Exception ex) {
            chatArea.append("Could not send Disconnect message. \n");
        }
        try {
            chatArea.append("Disconnected. \n");
            socket.close();
            userRemove(username);
        } catch (Exception ex) {
            chatArea.append("Failed to Disconnect. \n");
        }
        isConnected = false;
        usernameField.setEditable(true);
        usersList.setText("");
    }//GEN-LAST:event_disconnectButtonActionPerformed

    private void sendButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendButtonActionPerformed
        String message = inputArea.getText().trim();
        if (!message.isEmpty()) {
            try {
                // encrypt# : text area to writer that will send it to other clients. Only message
                String encryptedMessage = aes.encrypt(username + "#" + message + "#Chat");
                writer.println(encryptedMessage);
                writer.flush();
            } catch (Exception ex) {
                chatArea.append("Message was not sent. \n");
                ex.printStackTrace();
            }
        }
        inputArea.setText("");
        inputArea.requestFocus();
    }//GEN-LAST:event_sendButtonActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Client.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Client().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel activeUsersLabel;
    private javax.swing.JTextArea chatArea;
    private javax.swing.JButton connectButton;
    private javax.swing.JButton disconnectButton;
    private javax.swing.JTextArea inputArea;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JButton sendButton;
    private javax.swing.JTextField usernameField;
    private javax.swing.JLabel usernameLabel;
    private javax.swing.JTextArea usersList;
    // End of variables declaration//GEN-END:variables

    private void ListenThread() {
        Thread IncomingReader = new Thread(new IncomingReader());
        IncomingReader.start();
    }
}