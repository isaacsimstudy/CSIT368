import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class Receiver implements Runnable{
    private int rPort;
    private String rAddress;
    private boolean listen = true;
    public Receiver(String rAddress, int rPort) {
        System.out.println("Receiver\n");
        this.rPort = rPort;
        this.rAddress = rAddress;
    }
    public void run(){
        startReceiving();
    }
    private void startReceiving() {
        while (listen == true) {
            try (DatagramSocket socket = new DatagramSocket(rPort)) {
                byte[] buff = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buff, buff.length);
                System.out.println("Waiting for packet");
                socket.receive(packet);
                String received = new String(packet.getData(), 0, packet.getLength());
                System.out.println(received);
                InetAddress address = packet.getAddress();
                int port = packet.getPort();
                System.out.println("Address: " + address + " Port: " + port);
            } catch (Exception e) {
                System.out.println("Error in Receiver: " + e.getMessage());
            }
        }
    }

    public void stopReceiving() {
        listen = false;
    }
}
