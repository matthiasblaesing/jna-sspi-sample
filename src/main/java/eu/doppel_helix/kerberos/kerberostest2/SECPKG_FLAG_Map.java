package eu.doppel_helix.kerberos.kerberostest2;




import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;


public class SECPKG_FLAG_Map {
    private static final Map<Integer, String> SEC_MAP;
    
    static {
        Map<Integer, String> SEC_MAP_BUILDER = new HashMap<>();
        for (Field f : SspiX.class.getFields()) {
            if (f.getName().startsWith("SECPKG_FLAG_")) {
                try {
                    SEC_MAP_BUILDER.put(f.getInt(null), f.getName());
                } catch (IllegalArgumentException | IllegalAccessException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
        SEC_MAP = SEC_MAP_BUILDER;
    }
    
    public static List<String> resolve(int code) {
        List<String> result = new ArrayList<>();
        for(Entry<Integer,String> entry: SEC_MAP.entrySet()) {
            if((code & entry.getKey()) > 0) {
                result.add(entry.getValue());
            }
        }
        return result;
    }
}
