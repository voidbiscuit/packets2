import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import sniffer.PacketSniffer;

import java.io.*;
import java.lang.reflect.Array;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

class code {
    private static String clearscreenstring = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
    private static boolean scanstatus = false;


    // Packet Types
    public static final String ARP = "ARP";
    public static final String IPv4 = "IPv4";
    public static final String IPv6 = "IPv6";

    // Menu
    private static StringBuilder menu = new StringBuilder();


    public static void main(String[] args) throws UnknownHostException, PcapNativeException {

        // Get Menu
        try {
            BufferedReader r = new BufferedReader(new FileReader(new File("src\\main\\java\\menu.txt")));
            String line = "";
            while (line != null) {
                menu.append(line + "\n");
                line = r.readLine();
            }
        } catch (IOException e) {
            menu.append("No Menu");
            e.printStackTrace();
        }
        // User Choice
        Scanner scanner = new Scanner(System.in);
        char choice = ' ';

        // Initialise the packet sniffer

        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        System.out.println("number of devices: " + allDevs.size());
        for (PcapNetworkInterface device : allDevs) {
            System.out.println(device);

            List<PcapAddress> addresses = device.getAddresses();
            System.out.println("number of addresses: " + addresses.size());
            for (PcapAddress address : addresses) {
                System.out.println("\t" + address);
            }
        }


        PacketSniffer sniffer = new PacketSniffer("100.76.44.25"); //new PacketSniffer("10.104.2.31");
        sniffer.addProtocolFilter(ARP);
        sniffer.addProtocolFilter(IPv4);
        sniffer.addProtocolFilter(IPv6);
        clearScreen();
        while (choice != 'x') {
            System.out.println("Scan Filter : " + sniffer.getFilter());
            System.out.println("Scan Status : " + (scanstatus ? "Started" : "Stopped"));
            System.out.println(menu);
            choice = (scanner.nextLine() + " ").toLowerCase().charAt(0);
            clearScreen();
            switch (choice) {
                case 'a':
                    sniffer.addProtocolFilter(ARP);
                    break;
                case '4':
                    sniffer.addProtocolFilter(IPv4);
                    break;
                case '6':
                    sniffer.addProtocolFilter(IPv6);
                    break;
                case 't':
                    scanstatus = sniffer.startScan();
                    break;
                case 'y':
                    scanstatus = sniffer.stopScan();
                    break;
                case 'x':
                    scanstatus = sniffer.stopScan();
                    break;
                default:
                    System.out.println("Invalid key : " + choice);
                    break;
            }
        }
        sniffer.stopScan();
        scanner.close();
    }


    private static void clearScreen() {
        System.out.println(clearscreenstring);
    }

}

