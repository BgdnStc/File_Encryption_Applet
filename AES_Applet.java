package com.github.bgdnstc;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

@SuppressWarnings("DataFlowIssue")
public class AES_Applet extends Applet {
    private final AESKey key;
    private final byte[] iv;
    private Cipher cipher;
    private static final byte INS_ENCRYPT_DATA = (byte) 0x30;
    private static final byte INS_DECRYPT_DATA = (byte) 0x40;

    private AES_Applet() {
        byte[] keyBytes = new byte[16];
        for (byte i = 0; i < keyBytes.length; i++) {
            keyBytes[i] = i;
        }
        key = (AESKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_AES, JCSystem.MEMORY_TYPE_PERSISTENT, KeyBuilder.LENGTH_AES_128, false);
        key.setKey(keyBytes, (short) 0);
        iv = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
        Util.arrayFillNonAtomic(iv, (short) 0, (short) 16, (byte) 0x01);
        register();
    }

    public static void install(byte[] byteArray, short byteOffset, byte length) {
        new AES_Applet();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            return;
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_ENCRYPT_DATA:
                processEncryption(apdu, buffer);
                break;
            case INS_DECRYPT_DATA:
                processDecryption(apdu, buffer);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processEncryption(APDU apdu, byte[] buffer) {
        short dataLength;
        short dataOffset;
        if (buffer[ISO7816.OFFSET_LC] != 0) {
            dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
            dataOffset = ISO7816.OFFSET_CDATA;
        } else {
            dataLength = (short) (((buffer[5] & 0xFF) << 8) | (buffer[6] & 0xFF));
            dataOffset = 7;
        }
        if (dataLength <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short outputLength = dataLength % 16 == 0 ? dataLength : (short) (dataLength + (16 - dataLength % 16));
        byte[] output = new byte[outputLength];
        short outOffset = 0;
        aesEncryptInit();
        short bytesRead = apdu.setIncomingAndReceive();
        do {
            short updatedBytes = cipher.update(buffer, dataOffset, bytesRead, output, outOffset);
            outOffset += updatedBytes;
            bytesRead = apdu.receiveBytes(dataOffset);
        } while (bytesRead != 0);
        short lastBytes = cipher.doFinal(buffer, (short) 0, (short) 0, output, outOffset);
        outOffset += lastBytes;

        apdu.setOutgoing();
        apdu.setOutgoingLength(outOffset);
        short sentOffset = 0;
        while (outOffset > 0) {
            short chunk = (short) (outOffset > buffer.length ? buffer.length : outOffset);
            Util.arrayCopyNonAtomic(output, sentOffset, buffer, (short) 0, chunk);
            apdu.sendBytesLong(buffer, (short) 0, chunk);
            sentOffset += chunk;
            outOffset -= chunk;
        }
    }

    private void processDecryption(APDU apdu, byte[] buffer) {
        short dataLength;
        short dataOffset;
        if (buffer[ISO7816.OFFSET_LC] != 0) {
            dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
            dataOffset = ISO7816.OFFSET_CDATA;
        } else {
            dataLength = (short) (((buffer[5] & 0xFF) << 8) | (buffer[6] & 0xFF));
            dataOffset = 7;
        }
        if (dataLength <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short outputLength = dataLength;
        byte[] output = new byte[outputLength];
        short outOffset = 0;
        aesDecryptInit();
        short bytesRead = apdu.setIncomingAndReceive();
        do {
            short updatedBytes = cipher.update(buffer, dataOffset, bytesRead, output, outOffset);
            outOffset += updatedBytes;
            bytesRead = apdu.receiveBytes(dataOffset);
        } while (bytesRead != 0);
        short lastBytes = cipher.doFinal(buffer, (short) 0, (short) 0, output, outOffset);
        outOffset += lastBytes;

        apdu.setOutgoing();
        apdu.setOutgoingLength(outOffset);
        short sentOffset = 0;
        while (outOffset > 0) {
            short chunk = (short) (outOffset > buffer.length ? buffer.length : outOffset);
            Util.arrayCopyNonAtomic(output, sentOffset, buffer, (short) 0, chunk);
            apdu.sendBytesLong(buffer, (short) 0, chunk);
            sentOffset += chunk;
            outOffset -= chunk;
        }
    }

    private void aesEncryptInit() {
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, true);
        cipher.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 16);
    }

    private void aesDecryptInit() {
        cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, true);
        cipher.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) 16);
    }
}
