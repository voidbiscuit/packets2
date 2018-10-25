package sniffer.printpackets;

import java.util.ArrayList;

public class PacketPrinter {

    private static ArrayList<PacketData> packets = new ArrayList<>();
    private static int W_spacing = 1;
    private static int W_timestamp = 23;
    private static int W_protocol = 6;
    private static int W_IP = 32;
    private static int W_MAC = 28;

    private static String broadcast = "Broadcast";

    public static void initPacketPrinter() {
        addPacketTypes("ARP", "IPv4", "IPv6");
        addColumnToAll("%s", W_timestamp);
        addColumnToAll("(%s)", W_protocol);
        addColumnToAll("Src [%s]", W_IP);
        addColumnToAll("Dst [%s]", W_IP);

        // IPv4 Layout : Timestamp  (IPv4)     Src [ Source IP ]     Dst [ Destination IP ]
        // IPv6 Layout : Timestamp  (IPv6)     Src [ Source IP ]     Dst [ Destination IP ]
        // ARP Layout  : Timestamp  (ARP)      Src [ Source IP ]     Dst [ Destination IP ]     Src [ Source MAC ]     Dst [ Destination MAC ]

        addPacketColumn("ARP", "Src Mac [%s]", W_MAC);
        addPacketColumn("ARP", "Dst Mac [%s]", W_MAC);

        addPacketType("Host");
        addPacketColumn("Host", "IP %s", W_IP);
        addPacketColumn("Host", "MAC %s", W_MAC);

    }

    public static String printPacket(boolean debug, String packettype, ArrayList<String>... alldata) {
        int packetID = packetTypeExists(packettype);
        if (packetID < 0) return null;
        ArrayList<String> data = new ArrayList<>();
        for (int i = 0; i < alldata.length; i++)
            for (int j = 0; j < alldata[i].size(); j++)
                data.add(alldata[i].get(j));
        String outputdata = packets.get(packetID).printPacket(W_spacing, data);
        outputdata = outputdata.replaceAll("00\\:00\\:00\\:00\\:00\\:00", broadcast);
        if (debug) System.out.println(outputdata);
        return outputdata;
    }


    public static void addPacketTypes(String... packettypes) {
        for (String packettype : packettypes)
            addPacketType(packettype);
    }

    public static void addPacketType(String packettype) {
        if (packetTypeExists(packettype) < 0)
            packets.add(new PacketData(packettype));
    }

    public static void addPacketColumn(String packettype, String format, int width) {
        int packetID = packetTypeExists(packettype);
        if (packetID < 0) return;
        packets.get(packetID).addColumn(format, width);
    }

    public static void addColumnToAll(String format, int width) {
        for (int column = 0; column < packets.size(); column++)
            packets.get(column).addColumn(format, width);
    }

    private static int packetTypeExists(String packettype) {
        for (int i = 0; i < packets.size(); i++)
            if (packettype.equals(packets.get(i).getPackettype()))
                return i;
        return -1;
    }
}
