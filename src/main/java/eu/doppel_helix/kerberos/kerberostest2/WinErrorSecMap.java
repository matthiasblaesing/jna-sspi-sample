package eu.doppel_helix.kerberos.kerberostest2;




import com.sun.jna.platform.win32.WinError;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;


public class WinErrorSecMap {
    private static final Map<Integer, String> SEC_MAP;
    
    static {
        Map<Integer, String> SEC_MAP_BUILDER = new HashMap<>();
        for (Field f : WinError.class.getFields()) {
            if (f.getName().startsWith("SEC_")) {
                try {
                    SEC_MAP_BUILDER.put(f.getInt(null), f.getName());
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
        SEC_MAP = SEC_MAP_BUILDER;
    }
    
    public static String resolveString(int errorCode) {
        return SEC_MAP.get(errorCode);
    }
}
