package sniffer.network;

import sniffer.printpackets.PacketPrinter;

import java.util.ArrayList;
import java.util.Arrays;

public class ListHosts {
    private static ArrayList<String[]> hostlist = new ArrayList<>();
    private static String[] exclusions = new String[]
            {
                    "0.0.0.0"
            };

    public static boolean checkHost(ArrayList<String> data) {
        if (data.size() == 2)
            return checkHost(data.get(0), "") || checkHost(data.get(1), "");
        if (data.size() == 4)
            return checkHost(data.get(0), data.get(2)) || checkHost(data.get(1), data.get(3));
        return false;
    }

    private static boolean checkHost(String adr, String mac) {
        for (int i = 0; i < exclusions.length; i++)
            if (adr.equals(exclusions[i])) return false;


        // Wipe broadcast Address
        if (mac.equals("00\\:00\\:00\\:00\\:00\\:00")) mac = "";

        // For every host in the list, check for a matching IP address
        for (int i = 0; i < hostlist.size(); i++)
            if (hostlist.get(i)[0].equals(adr)) {
                // If the MAC address is empty, attempt to update with a correct MAC address
                if (hostlist.get(i)[1].equals("")) {
                    hostlist.set(i, new String[]{hostlist.get(i)[0], mac});
                    return true;
                }
                return false;
            }
        addHost(adr, mac);
        return true;
    }


    private static void addHost(String adr, String mac) {
        hostlist.add(new String[]{adr, mac});
    }

    public static void orderHosts(int column) {
        String[] ipA, ipB, fragments;
        int result;
        for (int i = 0; i < hostlist.size() - 1; i++) {
            ipA = hostlist.get(i)[column].split("\\.|:");
            for (int j = i + 1; j < hostlist.size(); j++) {
                ipB = hostlist.get(j)[column].split("\\.|:");
                for (int k = 0; k < ipA.length && k < ipB.length; k++) {
                    fragments = new String[]{ipA[k], ipB[k]};
                    while (fragments[0].length() < fragments[1].length()) fragments[0] = "0" + fragments[0];
                    while (fragments[1].length() < fragments[0].length()) fragments[1] = "0" + fragments[1];
                    ipA[k] = fragments[0];
                    ipB[k] = fragments[1];
                    result = fragments[0].compareTo(fragments[1]);
                    if (result > 0) {
                        String[] temp = hostlist.get(i);
                        hostlist.set(i, hostlist.get(j));
                        hostlist.set(j, temp);
                    }
                    if (result != 0)
                        break;
                }
            }
        }
    }

    public static String printHosts() {
        if (hostlist == null) return null;
        StringBuilder hostinfobuffer = new StringBuilder();
        for (int i = 0; i < hostlist.size(); i++)
            if (hostlist.get(i) != null)
                hostinfobuffer.append(PacketPrinter.printPacket(
                        false,
                        "Host",
                        new ArrayList<>(Arrays.asList(hostlist.get(i)))
                        ).trim() + "\n"
                );
        return hostinfobuffer.toString();
    }

    public static boolean checkPoison() {
        for (int i = 0; i < hostlist.size() - 1; i++) {
            if (!hostlist.get(i)[1].equals(""))
                for (int j = i + 1; j < hostlist.size(); j++) {
                    if (!hostlist.get(j)[1].equals(""))
                        if (hostlist.get(i)[1].equals(hostlist.get(j)[1])) {
                            System.out.println(hostlist.get(i)[1]);
                            return true;
                        }
                }
        }
        return false;
    }

    public static ArrayList<String[]> getHosts() {
        return hostlist;
    }

}
