package com.company;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Arrays;

/**
 * Created by user on 11/9/2016.
 */
public class MessageManager {

    public SecretKey key;
    public PrivateKey privateKey;
    public PublicKey PublicKey;
    public String pairKeyAlgorithmName = "RSA", desAlgorithmName = "DES";

    private Thread sender, receiver;
    private Cipher enCipher, deCipher;
    private KeyGenerator keygenerator;
    private int bitsNumber = 1024;

    public MessageManager(Socket socket) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {

        BufferedReader getline = new BufferedReader(new InputStreamReader(System.in));
        DataOutputStream send = new DataOutputStream(socket.getOutputStream());
        DataInputStream is = new DataInputStream(socket.getInputStream());

        //sending thread
        sender = new Thread(new Runnable() {
            @Override
            public void run() {
                while(true) {
                    try {
                        String sentence = getline.readLine();
                        send.write(encrypt(sentence));
                    } catch (IOException e) {
                        e.printStackTrace();
                        break;
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        break;
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                        break;
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                        break;
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                        break;
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                        break;
                    }
                }
            }
        });

        //receving thread
        receiver = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true){
                    try {
                        byte[] read = new byte[512];
                        int length = is.read(read);
                        byte[] encryptedBytes = Arrays.copyOfRange(read, 0, length);
                        System.out.println(decrypt(encryptedBytes));
                    } catch (IOException e) {
                        e.printStackTrace();
                        break;
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                        break;
                    } catch (IllegalBlockSizeException e) {
                        e.printStackTrace();
                        break;
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                        break;
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        break;
                    } catch (NoSuchPaddingException e) {
                        e.printStackTrace();
                        break;
                    }
                }
            }
        });
    }

    private String decrypt(byte[] message) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, UnsupportedEncodingException {
        deCipher = Cipher.getInstance(desAlgorithmName);
        deCipher.init(Cipher.DECRYPT_MODE, key);
        return new String(deCipher.doFinal(message));
    }

    private byte[] encrypt(String sentence) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        enCipher = Cipher.getInstance(desAlgorithmName);
        enCipher.init(Cipher.ENCRYPT_MODE, key);
        return enCipher.doFinal(sentence.getBytes());
    }

    public void sendMessage(){
        sender.start();
    }

    public void readMessage(){
        receiver.start();
    }

    public void generateKey() throws InvalidKeyException, NoSuchAlgorithmException {
        keygenerator = KeyGenerator.getInstance(desAlgorithmName);
        key = keygenerator.generateKey();
    }

    public void generatePairKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(pairKeyAlgorithmName);
        keyGen.initialize(bitsNumber);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        PublicKey = pair.getPublic();
    }

}
