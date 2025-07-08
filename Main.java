import javax.smartcardio.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            if (terminals.isEmpty()) {
                System.err.println("No card terminals available.");
            }
            CardTerminal terminal = terminals.getFirst();
            System.out.println("Using terminal: " + terminal.getName());
            if (!terminal.waitForCardPresent(5000)) {
                System.err.println("No card present.");
                return;
            }
            Card card = terminal.connect("*");
            System.out.println("Card: " + card);
            CardChannel cardChannel = card.getBasicChannel();
            byte[] aid = new byte[]{(byte) 0xA0, 0x00, 0x00, 0x00, 0x00, 0x01};
            CommandAPDU selectAPDU = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid);
            ResponseAPDU responseAPDU = cardChannel.transmit(selectAPDU);
            System.out.print("SELECT Response: ");
            byte[] response = responseAPDU.getBytes();
            for (byte b : response) {
                System.out.printf("%04X", b);
            }
            System.out.println();
            System.out.printf("SW: %04X%n", responseAPDU.getSW());
            if (responseAPDU.getSW() != 0x9000) {
                System.err.println("Applet selection failed.");
                card.disconnect(false);
                return;
            }


            File file = new File("sample.pdf");
            FileInputStream fileInputStream = new FileInputStream(file);
            BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
            byte[] plaintext = "".getBytes(StandardCharsets.UTF_8);

            CommandAPDU encryptAPDU = new CommandAPDU(0x00, 0x30, 0x00, 0x008D15, plaintext);
            responseAPDU = cardChannel.transmit(encryptAPDU);
            byte[] ciphertext = responseAPDU.getData();
            System.out.print("Ciphertext: ");
            for (byte b : ciphertext) {
                System.out.printf("%02X", b);
            }
            System.out.println();
            System.out.printf("SW: %04X%n", responseAPDU.getSW());

            CommandAPDU decryptAPDU = new CommandAPDU(0x00, 0x40, 0x00, 0x008D, ciphertext);
            responseAPDU = cardChannel.transmit(decryptAPDU);
            byte[] decryptedText = responseAPDU.getData();
            System.out.println("Plaintext: " + new String(decryptedText, StandardCharsets.UTF_8));
            System.out.printf("SW: %04X%n", responseAPDU.getSW());

            card.disconnect(false);

        } catch (CardException | FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}