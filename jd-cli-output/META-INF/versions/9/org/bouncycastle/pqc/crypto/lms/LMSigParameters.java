package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;

public class LMSigParameters {
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h5 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(5, 32, 5, NISTObjectIdentifiers.id_sha256);
  
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h10 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(6, 32, 10, NISTObjectIdentifiers.id_sha256);
  
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h15 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(7, 32, 15, NISTObjectIdentifiers.id_sha256);
  
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h20 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(8, 32, 20, NISTObjectIdentifiers.id_sha256);
  
  public static final org.bouncycastle.pqc.crypto.lms.LMSigParameters lms_sha256_n32_h25 = new org.bouncycastle.pqc.crypto.lms.LMSigParameters(9, 32, 25, NISTObjectIdentifiers.id_sha256);
  
  private static Map<Object, org.bouncycastle.pqc.crypto.lms.LMSigParameters> paramBuilders = (Map<Object, org.bouncycastle.pqc.crypto.lms.LMSigParameters>)new Object();
  
  private final int type;
  
  private final int m;
  
  private final int h;
  
  private final ASN1ObjectIdentifier digestOid;
  
  protected LMSigParameters(int paramInt1, int paramInt2, int paramInt3, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    this.type = paramInt1;
    this.m = paramInt2;
    this.h = paramInt3;
    this.digestOid = paramASN1ObjectIdentifier;
  }
  
  public int getType() {
    return this.type;
  }
  
  public int getH() {
    return this.h;
  }
  
  public int getM() {
    return this.m;
  }
  
  public ASN1ObjectIdentifier getDigestOID() {
    return this.digestOid;
  }
  
  static org.bouncycastle.pqc.crypto.lms.LMSigParameters getParametersForType(int paramInt) {
    return paramBuilders.get(Integer.valueOf(paramInt));
  }
}
