package org.bouncycastle.pqc.crypto.xmss;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Integers;

public final class XMSSMTParameters {
  private static final Map<Integer, XMSSMTParameters> paramsLookupTable;
  
  private final XMSSOid oid;
  
  private final XMSSParameters xmssParams;
  
  private final int height;
  
  private final int layers;
  
  public XMSSMTParameters(int paramInt1, int paramInt2, Digest paramDigest) {
    this(paramInt1, paramInt2, DigestUtil.getDigestOID(paramDigest.getAlgorithmName()));
  }
  
  public XMSSMTParameters(int paramInt1, int paramInt2, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    this.height = paramInt1;
    this.layers = paramInt2;
    this.xmssParams = new XMSSParameters(xmssTreeHeight(paramInt1, paramInt2), paramASN1ObjectIdentifier);
    this.oid = DefaultXMSSMTOid.lookup(getTreeDigest(), getTreeDigestSize(), getWinternitzParameter(), getLen(), getHeight(), paramInt2);
  }
  
  private static int xmssTreeHeight(int paramInt1, int paramInt2) throws IllegalArgumentException {
    if (paramInt1 < 2)
      throw new IllegalArgumentException("totalHeight must be > 1"); 
    if (paramInt1 % paramInt2 != 0)
      throw new IllegalArgumentException("layers must divide totalHeight without remainder"); 
    if (paramInt1 / paramInt2 == 1)
      throw new IllegalArgumentException("height / layers must be greater than 1"); 
    return paramInt1 / paramInt2;
  }
  
  public int getHeight() {
    return this.height;
  }
  
  public int getLayers() {
    return this.layers;
  }
  
  protected XMSSParameters getXMSSParameters() {
    return this.xmssParams;
  }
  
  protected WOTSPlus getWOTSPlus() {
    return this.xmssParams.getWOTSPlus();
  }
  
  protected String getTreeDigest() {
    return this.xmssParams.getTreeDigest();
  }
  
  public int getTreeDigestSize() {
    return this.xmssParams.getTreeDigestSize();
  }
  
  public ASN1ObjectIdentifier getTreeDigestOID() {
    return this.xmssParams.getTreeDigestOID();
  }
  
  int getWinternitzParameter() {
    return this.xmssParams.getWinternitzParameter();
  }
  
  protected int getLen() {
    return this.xmssParams.getLen();
  }
  
  protected XMSSOid getOid() {
    return this.oid;
  }
  
  public static XMSSMTParameters lookupByOID(int paramInt) {
    return paramsLookupTable.get(Integers.valueOf(paramInt));
  }
  
  static {
    HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
    hashMap.put(Integers.valueOf(1), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(2), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(3), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(4), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(5), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(6), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(7), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(8), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_sha256));
    hashMap.put(Integers.valueOf(9), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(10), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(11), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(12), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(13), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(14), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(15), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(16), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_sha512));
    hashMap.put(Integers.valueOf(17), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(18), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(19), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(20), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(21), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(22), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(23), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(24), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_shake128));
    hashMap.put(Integers.valueOf(25), new XMSSMTParameters(20, 2, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(26), new XMSSMTParameters(20, 4, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(27), new XMSSMTParameters(40, 2, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(28), new XMSSMTParameters(40, 4, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(29), new XMSSMTParameters(40, 8, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(30), new XMSSMTParameters(60, 3, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(31), new XMSSMTParameters(60, 6, NISTObjectIdentifiers.id_shake256));
    hashMap.put(Integers.valueOf(32), new XMSSMTParameters(60, 12, NISTObjectIdentifiers.id_shake256));
    paramsLookupTable = Collections.unmodifiableMap(hashMap);
  }
}
