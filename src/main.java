import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class main {
    static BigInteger p = new BigInteger("13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223");
    static BigInteger g = new BigInteger("5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796");

    static boolean serverRunning = true;
    static boolean clientRunning = true;


    public static void main(String[] args) throws IOException{
        System.out.println("File name: ");
        Scanner sc = new Scanner(System.in);
        String fileName = sc.nextLine();


        String [] fileInfo = new String[7];
        System.out.println("Enter Sender name");
        while(true){
            try {
                File file = new File(fileName);
                Scanner fileReader = new Scanner(file);
                int i = 0;
                while (fileReader.hasNextLine()) {
                    String line = fileReader.nextLine();
                    fileInfo[i] = line.split(" ")[1];
                    i++;
                }
                fileReader.close();
                break;
            } catch (Exception e) {
                System.out.println("File not found");
            }
        }

        Thread server = new Thread(new Runnable(){

            @Override
            public void run(){
                try {
                    System.out.println("Server started");
                    server(fileInfo[1], fileInfo[4], fileInfo[6]);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        Thread client = new Thread(new Runnable(){
            @Override
            public void run(){
                try {
                    System.out.println("Client started");
                    client(fileInfo[2], fileInfo[3], fileInfo[4], fileInfo[6]);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        server.start();
        client.start();
        while(server.isAlive() || client.isAlive()){
            if (!server.isAlive() || !client.isAlive()){
                System.out.println("Server: " + server.isAlive());
                System.out.println("Client: " + client.isAlive());
                try {
                    System.exit(0);
                    break;
                }
                catch (Exception e){
                    System.out.println("Error");
                }
            }
        }
    }

    public static void server(String receiverPort, String receiverPrivateKey, String senderPublicKey) throws IOException{
        BigInteger rPrivateKey = new BigInteger(receiverPrivateKey);
        BigInteger sPublicKey = new BigInteger(senderPublicKey);
        System.out.println("Receiver port: " + receiverPort);
        int port = Integer.parseInt(receiverPort);
        DatagramSocket ds = new DatagramSocket(port);
        byte[] receive = new byte[65535];

        DatagramPacket DpReceive = null;
        while (clientRunning)
        {
            System.out.println("Client running: " + clientRunning);
            if(!clientRunning){
                break;
            }
            // Step 2 : create a DatagramPacket to receive the data.
            DpReceive = new DatagramPacket(receive, receive.length);
            System.out.println("Waiting for client to send message");
            // Step 3 : receive the data in byte buffer.
            ds.receive(DpReceive);
            System.out.println("Client sent message");
            // Step 4 : convert the data from byte array to string.
            String receivedData = data(receive).toString();

            // Split the data by comma
            String[] receivedDataArray = receivedData.split(",");
            BigInteger gPowR = new BigInteger(receivedDataArray[0]);
            BigInteger C = new BigInteger(receivedDataArray[1]);
            String MAC = receivedDataArray[2];


            // TK = gPowR^remotePrivateKey mod p
            BigInteger TK = gPowR.modPow(rPrivateKey, p);

            // LK = localPublicKey^remotePrivateKey mod p
            BigInteger LK = sPublicKey.modPow(rPrivateKey, p);

            // Compute MAC= H(LK || gPowR || C || LK) where || is concatenation and H is SHA-1
            String MAC2 = LK.toString() + gPowR.toString() + C.toString() + LK.toString();
            byte[] messageDigest = null;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                MAC2 = Base64.getEncoder().encodeToString(md.digest(MAC2.getBytes()));
            }
            catch (Exception e) {
                System.out.println("Exception thrown"
                        + " for incorrect algorithm: " + e);
            }
            String receivedMessage = "";
            if (MAC.equalsIgnoreCase(MAC2)){
                // M' = D(TK, C)
                BigInteger M = C.divide(TK);
                // Convert to byte array then to string
                receivedMessage = new String(M.toByteArray());
                System.out.println("**The decryption on** \n" + data(receive) + "\n **is** \n" + receivedMessage);
            }
            else{

                System.out.println("Error");
            }

            // Exit the server if the client sends "bye"
            if (receivedMessage.equals("bye"))
            {
                System.out.println("Client sent bye.....EXITING");
                break;
            }

            // Clear the buffer after every message.
            receive = new byte[65535];
        }
    }
    public static StringBuilder data(byte[] a)
    {
        if (a == null)
            return null;
        StringBuilder ret = new StringBuilder();
        int i = 0;
        while (a[i] != 0)
        {
            ret.append((char) a[i]);
            i++;
        }
        return ret;
    }

    public static void client(String remoteIP, String remotePort, String lPrivateKey, String rPublicKey) throws IOException{
        BigInteger localPrivateKey = new BigInteger(lPrivateKey);
        BigInteger remotePublicKey = new BigInteger(rPublicKey);
        int port = Integer.parseInt(remotePort);
        System.out.println("Remote Port: " + port);
        Scanner sc = new Scanner(System.in);

        // Step 1:Create the socket object for
        // carrying the data.
        DatagramSocket ds = new DatagramSocket();
        InetAddress ip = InetAddress.getByName(remoteIP);
        byte buf[] = null;


        // loop while user not enters "bye"
        while (serverRunning)
        {
            System.out.println("Server running: " + serverRunning);
            if(!serverRunning){
                break;
            }
            // Taking input from user
            System.out.println("Enter the message to send");
            String inp = sc.nextLine();

            // convert the String input into the byte array.
            buf = inp.getBytes();

            // Get random number nonce r from 2 to p-1
            SecureRandom rRandom = new SecureRandom();
            BigInteger r = new BigInteger(p.bitLength(), rRandom);
            r = r.mod(p.subtract(BigInteger.ONE)).add(BigInteger.TWO);

            // g^r mod p
            BigInteger gPowR = g.modPow(r, p);

            // TK = remotePublicKey^r mod p
            BigInteger TK = remotePublicKey.modPow(r, p);

            // Use TK as key to encrypt message C = E(TK, M)
            BigInteger C = TK.multiply(new BigInteger(inp.getBytes()));

            // LK = remotePublicKey^localPrivateKey mod p
            BigInteger LK = remotePublicKey.modPow(localPrivateKey, p);

            // Compute MAC= H(LK || gPowR || C || LK) where || is concatenation and H is SHA-1
            String MAC = LK.toString() + gPowR.toString() + C.toString() + LK.toString();
            byte[] messageDigest = null;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                String mdString = Base64.getEncoder().encodeToString(md.digest(MAC.getBytes()));
                messageDigest = (gPowR.toString() + "," + C.toString() + "," + mdString).getBytes();
            }
            catch (Exception e) {
                System.out.println("Exception thrown"
                        + " for incorrect algorithm: " + e);
            }

            // Step 2 : Create the datagramPacket for sending the packet
            // to the server that consists of (gPowR, C, MAC)
            DatagramPacket DpSend =
                    new DatagramPacket(messageDigest, messageDigest.length, ip, port);

            // Step 3 : invoke the send call to actually send
            // the data and print buf
            System.out.println("Sending message: " + inp + "," + messageDigest);
            ds.send(DpSend);

            // break the loop if user enters "bye"
            if (inp.equals("bye"))
                break;
        }

    }

}