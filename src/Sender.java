import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import javax.crypto.*;
import java.security.*;
public class Sender {
    private int sPort;
    private String sAddress;
    public Sender(String sAddress, int sPort){
        this.sPort = sPort;
        this.sAddress = sAddress;
    }

    public void sendMessage(int gPower, byte[] message, byte[] mac){
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress address = InetAddress.getByName("sAddress");
            // Things to send are gPower, message and mac
            byte[] buff = new byte[1024];
            buff[0] = (byte) gPower;
            for(int i = 1; i < 1024; i++){
                buff[i] = message[i-1];
            }
            for(int i = 513; i < 1024; i++){
                buff[i] = mac[i-513];
            }
            DatagramPacket packet = new DatagramPacket(buff, buff.length, address, sPort);
            socket.send(packet);
            System.out.println("Message sent");
        } catch (Exception e) {
            System.out.println("Error in Sender: " + e.getMessage());
        }
    }
}
