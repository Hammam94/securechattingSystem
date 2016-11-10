package com.company;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Enumeration;

/**
 * Created by user on 11/2/2016.
 */
public class Server {
    private static int serverPort = 23444, arraySize = 128;
    private static InetAddress inetAddress;
    private static String request, response;
    private static ServerSocket socket;
    private static Socket connection;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, ClassNotFoundException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        setInetAddress();
        socket = new ServerSocket(serverPort, 1, inetAddress);
        connection = socket.accept();
        MessageManager msg = new MessageManager(connection);
        msg.generatePairKey();

        //send my public key
        ObjectOutputStream obOut = new ObjectOutputStream(connection.getOutputStream());
        obOut.writeObject(msg.PublicKey);
        obOut.flush();

        //receiving the encrypted bytes for des key
        DataInputStream is = new DataInputStream(connection.getInputStream());
        byte[] receviedbytes = new byte[arraySize];
        is.read(receviedbytes);

        //decrypt using my private key and get the DES key
        Cipher dencrypt=Cipher.getInstance(msg.pairKeyAlgorithmName);
        dencrypt.init(Cipher.DECRYPT_MODE, msg.privateKey);
        byte[] decryptedBytes = dencrypt.doFinal(receviedbytes);
        msg.key = new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, msg.desAlgorithmName);

        //start sending and receiving threads
        msg.readMessage();
        msg.sendMessage();
    }

    private static void setInetAddress(){
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                if (intf.getName().contains("wlan")) {
                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr
                            .hasMoreElements();) {
                        inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLoopbackAddress()
                                && (inetAddress.getAddress().length == 4)) {
                            System.out.println (inetAddress.getHostAddress());
                        }
                    }
                }
            }
        } catch (SocketException ex) {
            System.out.println (ex.toString());
        }
    }
}