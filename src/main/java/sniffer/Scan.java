package sniffer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.*;
import org.pcap4j.util.MacAddress;
import sniffer.network.ListHosts;
import sniffer.GUI.infobox;
import sniffer.printpackets.PacketPrinter;

import java.sql.Timestamp;
import java.util.ArrayList;

import static sniffer.network.ListHosts.checkHost;
import static sniffer.network.ListHosts.checkPoison;
import static sniffer.network.ListHosts.orderHosts;

public class Scan implements Runnable {
    private PcapHandle handle;
    private ArrayList<String> filter;
    private Timestamp timestamp;

    // Windows
    private infobox snifferinfo, hostinfo;
    private String sniffertitle = "Tim's Packet Sniffer : Scan initialised at %s Filter : %s";
    private String hosttitle = "Hosts";

    public Scan(PcapHandle handle, ArrayList<String> filter) {
        this.handle = handle;
        this.filter = filter;
    }

    public void run() {

        // Create User Interfaces
        snifferinfo = new infobox(500, 0, 1300, 600, sniffertitle); // Create Sniffer Info
        hostinfo = new infobox(0, 0, 500, 600, hosttitle);        // Create Host Info

        // Initialise User Interface Data
        timestamp = new Timestamp(System.currentTimeMillis());
        snifferinfo.setTitle(String.format(sniffertitle, timestamp, filter));

        // Initialise Packet
        Packet packet = null;

        // While the thread is open
        while (!Thread.interrupted()) {
            try {
                // Scan for packets until one is detected (which is not null)
                packet = scanNextPacket(handle);
            } catch (NotOpenException e) {
                // If it's fucked, throw
                e.printStackTrace();
                System.err.println("Handle is closed");
            }
            // Check again for null packets before processing
            if (packet != null)
                processPacket(packet, filter);
        }
        // Destroy the UIs
        snifferinfo.nuke();
        hostinfo.nuke();
    }


    private Packet scanNextPacket(PcapHandle handle) throws NotOpenException {
        Packet packet = null;
        while (packet == null) packet = handle.getNextPacket();
        return packet;
    }

    private boolean processPacket(Packet packet, ArrayList<String> filter) {
        // Convert Packet to Ethernet Packet
        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        String etherType = ethernetPacket.getHeader().getType().name();

        // Filter
        boolean discard = true;
        for (String packetmatch : filter)
            if (etherType.matches(packetmatch)) discard = false;
        if (discard) return false;

        // Get Data
        ArrayList<String> metadata = new ArrayList<>();
        ArrayList<String> data = new ArrayList<>();
        timestamp = new Timestamp(System.currentTimeMillis());
        metadata.add(timestamp.toString());
        metadata.add(etherType);

        // Get Data for each type of packet
        switch (etherType) {
            case "ARP":
                ArpPacket arpPacket = packet.get(ArpPacket.class);          // ARP Packet
                ArpPacket.ArpHeader arpHeader = arpPacket.getHeader();      // ARP Header
                data.add(arpHeader.getSrcProtocolAddr().getHostAddress());  // Source IP
                data.add(arpHeader.getDstProtocolAddr().getHostAddress());  // Destination IP
                data.add(arpHeader.getSrcHardwareAddr().toString());        // Source MAC
                data.add(arpHeader.getDstHardwareAddr().toString());        // Destination Mac
                break;
            case "IPv4":
                IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);       // IPv4 Packet
                IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();  // IPv4 Header
                data.add(ipV4Header.getSrcAddr().getHostAddress());         // Source IP
                data.add(ipV4Header.getDstAddr().getHostAddress());         // Destination IP
                break;
            case "IPv6":
                IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);       // IPv6 Packet
                IpV6Packet.IpV6Header ipV6Header = ipV6Packet.getHeader();  // IPv6 Header
                data.add(ipV6Header.getSrcAddr().getHostAddress());         // Source IP
                data.add(ipV6Header.getDstAddr().getHostAddress());         // Destination IP
                break;
        }

        // Update Host List
        if (checkHost(data)) {
            orderHosts(0);
            hostinfo.setText(ListHosts.printHosts());
        }
        if (checkPoison())
            hostinfo.setTitle("Poisoned");

        // Log Packet
        snifferinfo.append(PacketPrinter.printPacket(false, etherType, metadata, data).trim() + "\n");


        // Process Packet


        return true;
    }
}
