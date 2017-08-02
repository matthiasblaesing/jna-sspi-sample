
package eu.doppel_helix.kerberos.kerberostest2;

import com.sun.jna.platform.win32.WinError;

public class CommonUtil {

    private CommonUtil() {}
    
    public static void ensureOk(int result) {
        if (result != WinError.SEC_E_OK) {
            throw new IllegalStateException(String.format("Call failed (%d): %s", result, WinErrorSecMap.resolveString(result)));
        }
    }
    
    public static boolean SEC_SUCCESS(int result) {
        return result >= 0;
    }

    private static final String[] hexDigits = new String[]{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    public static void printHexDump(byte[] data) {
        StringBuilder rowBuffer = new StringBuilder(100);
        for (int rowOffset = 0; rowOffset < data.length; rowOffset += 16) {
            rowBuffer.append(String.format("%04x | ", rowOffset));
            for (int i = 0; i < 16; i++) {
                if ((rowOffset + i) < data.length) {
                    byte dataElement = data[rowOffset + i];
                    rowBuffer.append(hexDigits[(dataElement >> 4) & 0x0F]);
                    rowBuffer.append(hexDigits[dataElement & 0x0F]);
                } else {
                    rowBuffer.append("  ");
                }
                if (i == 7) {
                    rowBuffer.append(":");
                } else {
                    rowBuffer.append(" ");
                }
            }
            rowBuffer.append(" | ");
            for (int i = 0; i < 16; i++) {
                if ((rowOffset + i) < data.length) {
                    char c = (char) data[rowOffset + i];
                    if (Character.isWhitespace(c) || c == 0) {
                        rowBuffer.append(" ");
                    } else {
                        rowBuffer.append(c);
                    }
                }
            }
            System.out.println(rowBuffer.toString());
            rowBuffer.setLength(0);
        }
    }
}
