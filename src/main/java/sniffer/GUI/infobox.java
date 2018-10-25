package sniffer.GUI;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

public class infobox {
    private JFrame infobox;
    private JTextArea infotext;
    private JScrollPane infoscroller;
    private String titleformat;

    public infobox(int x, int y, int w, int h, String titleformat) {

        infobox = new JFrame();
        infobox.setBounds(x, y, w, h);
        infobox.setAlwaysOnTop(true);
        this.titleformat = titleformat;
        {
            {
                infotext = new JTextArea();
                infotext.setEditable(false);
                infotext.setFont(new Font("monospaced", Font.PLAIN, 12));
            }
            infoscroller = new JScrollPane(infotext);
            infoscroller.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        }
        infobox.getContentPane().add(infoscroller);
        resizeWindow();
        infobox.addComponentListener(new ComponentAdapter() {
            public void componentResized(ComponentEvent evt) {
                resizeWindow();
            }
        });
        infobox.setVisible(true);
    }

    private void resizeWindow() {
        infoscroller.setBounds(0, 0, infobox.getWidth(), infobox.getHeight());
        infobox.revalidate();
        infobox.repaint();
    }

    public void setTitle(String title) {
        infobox.setTitle(title);
    }

    public void nuke() {
        infobox.dispose();
        infotext = null;
        infoscroller = null;
        titleformat = "";
    }

    public void append(String text) {
        infotext.append(text);
    }

    public void setText(String text) {
        infotext.setText(text);
    }

    public int getWidth() {
        return infobox.getWidth();
    }

    public int getHeight() {
        return infobox.getHeight();
    }

}
