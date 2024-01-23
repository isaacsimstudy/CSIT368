import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Scanner;

public class main {

    public static void main(String[] args) throws IOException{
        BigInteger p = new BigInteger("13232376895198612407547930718267435757728527029623408872245156039757713029036368719146452186041204237350521785240337048752071462798273003935646236777459223");
        BigInteger g = new BigInteger("5421644057436475141609648488325705128047428394380474376834667300766108262613900542681289080713724597310673074119355136085795982097390670890367185141189796");
        BigInteger remotePublicKey = new BigInteger("629793796486995664080725752407537496794064786113392023999505216348694311366900579329784301605019270546150577068917545520648019990781107715819556898683513");
        BigInteger remotePrivateKey = new BigInteger("6255983986685995629823699191343964199066558780564601644115388277120319993596327698381872009667378867633811920977825989397259798891964470515483469208807054");
        BigInteger localPrivateKey = new BigInteger("11868526698511104855084256721330480674148301246409598143612631864097107400818064908564819949520988188891225978290102013612734826744059486075587544325105037");
        BigInteger localPublicKey = new BigInteger("13048340261633346571846928341279963048816713985911861666997289538565904008394415467724767926107467276847567327556571491326784158578821209230090090922706869");
        BigInteger sharedSecretKey;
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

            System.out.println("Client:-" + data(receive));

            // Exit the server if the client sends "bye"
            if (data(receive).toString().equals("bye"))
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

            // Step 2 : Create the datagramPacket for sending
            // the data.
            DatagramPacket DpSend =
                    new DatagramPacket(buf, buf.length, ip, 1234);

            // Step 3 : invoke the send call to actually send
            // the data.
            ds.send(DpSend);

            // break the loop if user enters "bye"
            if (inp.equals("bye"))
                break;
        }
    }

}
