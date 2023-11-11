package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.xmss.XMSSOid;

final class WOTSPlusOid implements XMSSOid {
  private static final Map<String, org.bouncycastle.pqc.crypto.xmss.WOTSPlusOid> oidLookupTable;
  
  private final int oid;
  
  private final String stringRepresentation;
  
  static {
    HashMap<Object, Object> hashMap = new HashMap<>();
    hashMap.put(createKey("SHA-256", 32, 16, 67), new org.bouncycastle.pqc.crypto.xmss.WOTSPlusOid(16777217, "WOTSP_SHA2-256_W16"));
    hashMap.put(createKey("SHA-512", 64, 16, 131), new org.bouncycastle.pqc.crypto.xmss.WOTSPlusOid(33554434, "WOTSP_SHA2-512_W16"));
    hashMap.put(createKey("SHAKE128", 32, 16, 67), new org.bouncycastle.pqc.crypto.xmss.WOTSPlusOid(50331651, "WOTSP_SHAKE128_W16"));
    hashMap.put(createKey("SHAKE256", 64, 16, 131), new org.bouncycastle.pqc.crypto.xmss.WOTSPlusOid(67108868, "WOTSP_SHAKE256_W16"));
    oidLookupTable = Collections.unmodifiableMap(hashMap);
  }
  
  private WOTSPlusOid(int paramInt, String paramString) {
    this.oid = paramInt;
    this.stringRepresentation = paramString;
  }
  
  protected static org.bouncycastle.pqc.crypto.xmss.WOTSPlusOid lookup(String paramString, int paramInt1, int paramInt2, int paramInt3) {
    if (paramString == null)
      throw new NullPointerException("algorithmName == null"); 
    return oidLookupTable.get(createKey(paramString, paramInt1, paramInt2, paramInt3));
  }
  
  private static String createKey(String paramString, int paramInt1, int paramInt2, int paramInt3) {
    if (paramString == null)
      throw new NullPointerException("algorithmName == null"); 
    return paramString + "-" + paramString + "-" + paramInt1 + "-" + paramInt2;
  }
  
  public int getOid() {
    return this.oid;
  }
  
  public String toString() {
    return this.stringRepresentation;
  }
}
