package sniffer;

import org.pcap4j.core.*;
import sniffer.printpackets.PacketPrinter;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

public class PacketSniffer {

    //  PCAP Network Objects
    private PcapNetworkInterface networkInterface;
    private PcapHandle handle;
    private Thread scan;

    // Packet Data
    private ArrayList<String> filter = new ArrayList<>();

    public PacketSniffer(String localaddress) {
        PacketPrinter.initPacketPrinter();  // Initialiize PacketPrinter
        try {
            InetAddress local = InetAddress.getByName(localaddress);
            Thread.sleep(1000);
            this.networkInterface = Pcaps.getDevByName(localaddress);
            this.handle = networkInterface.openLive(12, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 1000);
        } catch (PcapNativeException | UnknownHostException e) {
            System.err.println("No host, or other PCAP error");
            e.printStackTrace();
        } catch (InterruptedException | NullPointerException e ) {
            System.err.println("fuck");
            e.printStackTrace();
        }
    }

    public void addProtocolFilter(String protocol) {
        if (this.filter.contains(protocol))
            this.filter.remove(protocol);
        else
            this.filter.add(protocol);
    }

    public ArrayList<String> getFilter() {
        return filter;
    }

    public boolean startScan() {
        if (scan == null || scan.isInterrupted()) {
            if (filter.size() == 0) return false;
            scan = new Thread(new Scan(handle, filter));
        }
        if (scan.isAlive()) {
            return true;
        }
        scan.start();
        return true;
    }

    public boolean stopScan() {
        if (scan == null)
            return false;
        if (scan.isInterrupted())
            return false;
        scan.interrupt();
        scan = null;
        return false;
    }
}
