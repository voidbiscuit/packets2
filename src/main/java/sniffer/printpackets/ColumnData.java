package sniffer.printpackets;

public class ColumnData {

    private String format;
    private int width;

    public ColumnData(String format, int width) {
        this.format = format;
        this.width = width;
    }

    public String getColumn(String data, int spacing) {
        StringBuilder returnval = new StringBuilder();
        returnval.append(String.format(format, data));
        for (int i = width + spacing; i > data.length(); i--)
            returnval.append(" ");
        return returnval.toString();
    }
}
