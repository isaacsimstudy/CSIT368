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
    static BigInteger remotePublicKey = new BigInteger("629793796486995664080725752407537496794064786113392023999505216348694311366900579329784301605019270546150577068917545520648019990781107715819556898683513");
    static BigInteger remotePrivateKey = new BigInteger("6255983986685995629823699191343964199066558780564601644115388277120319993596327698381872009667378867633811920977825989397259798891964470515483469208807054");
    static BigInteger localPrivateKey = new BigInteger("11868526698511104855084256721330480674148301246409598143612631864097107400818064908564819949520988188891225978290102013612734826744059486075587544325105037");
    static BigInteger localPublicKey = new BigInteger("13048340261633346571846928341279963048816713985911861666997289538565904008394415467724767926107467276847567327556571491326784158578821209230090090922706869");

    public static void main(String[] args) throws IOException{

        Thread server = new Thread(new Runnable(){
            @Override
            public void run(){
                try {
                    server();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        Thread client = new Thread(new Runnable(){
            @Override
            public void run(){
                try {
                    client();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        server.start();
        client.start();
    }

    public static void server() throws IOException{
        DatagramSocket ds = new DatagramSocket(1234);
        byte[] receive = new byte[65535];

        DatagramPacket DpReceive = null;
        while (true)
        {
            // Step 2 : create a DatagramPacket to receive the data.
            DpReceive = new DatagramPacket(receive, receive.length);

            // Step 3 : receive the data in byte buffer.
            ds.receive(DpReceive);

            // Step 4 : convert the data from byte array to string.
            String receivedData = data(receive).toString();

            // Split the data by comma
            String[] receivedDataArray = receivedData.split(",");
            BigInteger gPowR = new BigInteger(receivedDataArray[0]);
            BigInteger C = new BigInteger(receivedDataArray[1]);
            String MAC = receivedDataArray[2];
            System.out.println("MAC: " + MAC);


            // TK = gPowR^remotePrivateKey mod p
            BigInteger TK = gPowR.modPow(remotePrivateKey, p);
            System.out.println("TK: " + TK);

            // LK = localPublicKey^remotePrivateKey mod p
            BigInteger LK = localPublicKey.modPow(remotePrivateKey, p);
            System.out.println("LK: " + LK);

            // Compute MAC= H(LK || gPowR || C || LK) where || is concatenation and H is SHA-1
            String MAC2 = LK.toString() + gPowR.toString() + C.toString() + LK.toString();
            byte[] messageDigest = null;
            System.out.println("MAC2: " + MAC2);
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

    public static void client() throws IOException{
        Scanner sc = new Scanner(System.in);

        // Step 1:Create the socket object for
        // carrying the data.
        DatagramSocket ds = new DatagramSocket();


        InetAddress ip = InetAddress.getLocalHost();
        byte buf[] = null;


        // loop while user not enters "bye"
        while (true)
        {
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
            System.out.println("gPowR: " + gPowR);

            // TK = remotePublicKey^r mod p
            BigInteger TK = remotePublicKey.modPow(r, p);
            System.out.println("TK: " + TK);

            // Use TK as key to encrypt message C = E(TK, M)
            BigInteger C = TK.multiply(new BigInteger(inp.getBytes()));
            System.out.println("C: " + C);

            // LK = remotePublicKey^localPrivateKey mod p
            BigInteger LK = remotePublicKey.modPow(localPrivateKey, p);
            System.out.println("LK: " + LK);

            // Compute MAC= H(LK || gPowR || C || LK) where || is concatenation and H is SHA-1
            String MAC = LK.toString() + gPowR.toString() + C.toString() + LK.toString();
            System.out.println("MAC: " + MAC);
            byte[] messageDigest = null;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                String mdString = Base64.getEncoder().encodeToString(md.digest(MAC.getBytes()));
                System.out.println("mdString: " + mdString);
                messageDigest = (gPowR.toString() + "," + C.toString() + "," + mdString).getBytes();
            }
            catch (Exception e) {
                System.out.println("Exception thrown"
                        + " for incorrect algorithm: " + e);
            }

            // Step 2 : Create the datagramPacket for sending the packet
            // to the server that consists of (gPowR, C, MAC)
            DatagramPacket DpSend =
                    new DatagramPacket(messageDigest, messageDigest.length, ip, 1234);

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