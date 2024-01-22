import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.math.BigInteger;

public class main {

    public static void main(String[] args) {
        int choice = 6;
        String[] ip = new String[4];
        Receiver receive = null;
        Thread receivingThread = null;
        Sender send = null;
        int localPublicKey = 0;
        int remotePublicKey = 0;
        int p = 0;
        int g = 0;
        int localSecretKey = 0;
        System.out.println("Choose the following options ");
        System.out.println("Always start with option 1 first");
        System.out.println("1. Read the file");
        System.out.println("2. Start Receiving");
        System.out.println("3. Send Message");
        System.out.println("4. Stop Receiving");
        System.out.println("5. Generate Keys");
        System.out.println("6. Exit");
        while(true){
            System.out.println("Enter your choice: ");
            Scanner sc = new Scanner(System.in);
            choice = sc.nextInt();
            sc.nextLine();
            if(choice < 1 || choice > 6){
                System.out.println("Invalid choice");
            }
            switch (choice) {
                case 1 -> {
                    System.out.println("Enter the file name with full absolute path: ");
                    String fileName = sc.nextLine();
                    System.out.println("File name is: " + fileName);
                    ip = readFile(fileName);
                    //print the whole array
                    for (String s : ip) {
                        System.out.println(s);
                    }
                }
                case 2 -> {
                    receive = new Receiver(ip[1], Integer.parseInt(ip[3]));
                    receivingThread = new Thread(receive);
                    receivingThread.start();
                }
                case 3 -> {
                    send = new Sender(ip[0], Integer.parseInt(ip[2]));
                    while (true) {
                        // Zp and g
                        SecureRandom secureRandom = new SecureRandom();
                        BigInteger Zp = BigInteger.valueOf(p);
                        BigInteger G = BigInteger.valueOf(g);

                        //nonce
                        BigInteger nonce = new BigInteger(Zp.bitLength(), secureRandom).mod(Zp);
                        if (nonce.equals(BigInteger.ZERO)) {
                            nonce = BigInteger.ONE;
                        }

                        // g^nonce
                        int gPower = G.pow(nonce.intValue()).intValue();

                        // tempKey
                        int tempKey = remotePublicKey ^ nonce.intValue();

                        // message to send
                        System.out.println("Enter the message to send: ");
                        String message = sc.nextLine();

                        // encrypt message
                        byte[] encryptedMessage = null;
                        try {
                            byte[] bytesKey = ByteBuffer.allocate(32).putInt(tempKey).array();
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                            Key secretKeySpec = new SecretKeySpec(bytesKey, "AES");
                            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                            encryptedMessage = cipher.doFinal(message.getBytes());
                        } catch (Exception e) {
                            System.out.println("Error in encrypting message: " + e.getMessage());
                        }

                        // Compute Long-Term Key
                        int longTermKey = remotePublicKey ^ localSecretKey;

                        // Compute MAC where MAC = H(longTermKey || gPower || encryptedMessage || longTermKey)
                        byte[] mac = null;
                        try {
                            byte[] bytesKey = ByteBuffer.allocate(4).putInt(longTermKey).array();
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                            Key secretKeySpec = new SecretKeySpec(bytesKey, "SHA-1");
                            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                            mac = cipher.doFinal((longTermKey + String.valueOf(gPower) + encryptedMessage + longTermKey).getBytes());
                        } catch (Exception e) {
                            System.out.println("Error in computing MAC: " + e.getMessage());
                        }

                        // send message
                        send.sendMessage(gPower, encryptedMessage, mac);
                        System.out.println("Do you want to send more messages? (y/n)");
                        String ans = sc.nextLine();
                        if (ans.equals("n")) {
                            break;
                        }
                    }
                }
                case 4 -> {
                    System.out.println("Stop Receiving");
                    receivingThread.interrupt();
                    //receive.stopReceiving();
                }
                case 5 -> {
                    System.out.println("Enter the value of p: ");
                    p = sc.nextInt();
                    System.out.println("Enter the value of g: ");
                    g = sc.nextInt();
                    System.out.println("Enter the value of remote public key: ");
                    remotePublicKey = sc.nextInt();
                    System.out.println("Enter the value of local secret key: ");
                    localSecretKey = sc.nextInt();
                }
                case 6 -> {
                    System.out.println("Exit");
                    System.exit(0);
                }
                default -> System.out.println("Invalid choice");
            }
        }
    }
    public static String[] readFile(String fileName) {
        String[] ip = new String[4];
        int j = 0;
        try {
            File fileReader = new File(fileName);
            Scanner myReader = new Scanner(fileReader);
            while (myReader.hasNextLine() && j < ip.length) {
                String data = myReader.nextLine();
                ip[j] = data.split(" ")[1];
                j++;
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        return ip;
    }

}
