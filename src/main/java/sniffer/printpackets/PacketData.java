package sniffer.printpackets;

import java.util.ArrayList;

public class PacketData {
    private String packettype;
    private ArrayList<ColumnData> columndata = new ArrayList<>();

    public PacketData(String packettype) {
        this.packettype = packettype;
    }

    public String getPackettype() {
        return packettype;
    }

    public void addColumn(String format, int width) {
        columndata.add(new ColumnData(format, width));
    }

    public String printPacket(int spacing, ArrayList<String> data) {
        StringBuilder output = new StringBuilder();
        for (int column = 0; column < data.size(); column++)
            output.append(columndata.get(column).getColumn(data.get(column), spacing));
        return output.toString();
    }
}
