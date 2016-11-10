package com.company;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Enumeration;

/**
 * Created by user on 11/2/2016.
 */
public class Client {
    private static InetAddress inetAddress;
    private static Socket socket;
    private static String sentence;
    private static int portNumber = 23444;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, ClassNotFoundException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        setInetAddress();

        socket = new Socket(inetAddress.getHostAddress(), portNumber);
        MessageManager msg = new MessageManager(socket);
        msg.generateKey();

        //get public key
        ObjectInputStream obIn = new ObjectInputStream(socket.getInputStream());
        Object obj = obIn.readObject();
        msg.PublicKey = (PublicKey) obj;

        DataOutputStream send = new DataOutputStream(socket.getOutputStream());

        //encrypt the des key then send it
        Cipher encrypt=Cipher.getInstance(msg.pairKeyAlgorithmName);
        encrypt.init(Cipher.ENCRYPT_MODE, msg.PublicKey);
        byte[] wrapped = encrypt.doFinal(msg.key.getEncoded());
        send.write(wrapped);

        //start sending and receiving threads
        msg.sendMessage();
        msg.readMessage();
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
