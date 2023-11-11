package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class DefaultXMSSOid implements XMSSOid {
  private static final Map<String, DefaultXMSSOid> oidLookupTable;
  
  private final int oid;
  
  private final String stringRepresentation;
  
  private DefaultXMSSOid(int paramInt, String paramString) {
    this.oid = paramInt;
    this.stringRepresentation = paramString;
  }
  
  public static DefaultXMSSOid lookup(String paramString, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    if (paramString == null)
      throw new NullPointerException("algorithmName == null"); 
    return oidLookupTable.get(createKey(paramString, paramInt1, paramInt2, paramInt3, paramInt4));
  }
  
  private static String createKey(String paramString, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    if (paramString == null)
      throw new NullPointerException("algorithmName == null"); 
    return paramString + "-" + paramInt1 + "-" + paramInt2 + "-" + paramInt3 + "-" + paramInt4;
  }
  
  public int getOid() {
    return this.oid;
  }
  
  public String toString() {
    return this.stringRepresentation;
  }
  
  static {
    HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
    hashMap.put(createKey("SHA-256", 32, 16, 67, 10), new DefaultXMSSOid(1, "XMSS_SHA2_10_256"));
    hashMap.put(createKey("SHA-256", 32, 16, 67, 16), new DefaultXMSSOid(2, "XMSS_SHA2_16_256"));
    hashMap.put(createKey("SHA-256", 32, 16, 67, 20), new DefaultXMSSOid(3, "XMSS_SHA2_20_256"));
    hashMap.put(createKey("SHA-512", 64, 16, 131, 10), new DefaultXMSSOid(4, "XMSS_SHA2_10_512"));
    hashMap.put(createKey("SHA-512", 64, 16, 131, 16), new DefaultXMSSOid(5, "XMSS_SHA2_16_512"));
    hashMap.put(createKey("SHA-512", 64, 16, 131, 20), new DefaultXMSSOid(6, "XMSS_SHA2_20_512"));
    hashMap.put(createKey("SHAKE128", 32, 16, 67, 10), new DefaultXMSSOid(7, "XMSS_SHAKE_10_256"));
    hashMap.put(createKey("SHAKE128", 32, 16, 67, 16), new DefaultXMSSOid(8, "XMSS_SHAKE_16_256"));
    hashMap.put(createKey("SHAKE128", 32, 16, 67, 20), new DefaultXMSSOid(9, "XMSS_SHAKE_20_256"));
    hashMap.put(createKey("SHAKE256", 64, 16, 131, 10), new DefaultXMSSOid(10, "XMSS_SHAKE_10_512"));
    hashMap.put(createKey("SHAKE256", 64, 16, 131, 16), new DefaultXMSSOid(11, "XMSS_SHAKE_16_512"));
    hashMap.put(createKey("SHAKE256", 64, 16, 131, 20), new DefaultXMSSOid(12, "XMSS_SHAKE_20_512"));
    oidLookupTable = Collections.unmodifiableMap(hashMap);
  }
}
