package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.DigestUtil;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsSignature;
import org.bouncycastle.pqc.crypto.lms.LMSContext;
import org.bouncycastle.pqc.crypto.lms.LMSSignature;
import org.bouncycastle.pqc.crypto.lms.LmsUtils;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

class LMOtsPublicKey implements Encodable {
  private final LMOtsParameters parameter;
  
  private final byte[] I;
  
  private final int q;
  
  private final byte[] K;
  
  public LMOtsPublicKey(LMOtsParameters paramLMOtsParameters, byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    this.parameter = paramLMOtsParameters;
    this.I = paramArrayOfbyte1;
    this.q = paramInt;
    this.K = paramArrayOfbyte2;
  }
  
  public static org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey getInstance(Object paramObject) throws Exception {
    if (paramObject instanceof org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey)
      return (org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey)paramObject; 
    if (paramObject instanceof DataInputStream) {
      LMOtsParameters lMOtsParameters = LMOtsParameters.getParametersForType(((DataInputStream)paramObject).readInt());
      byte[] arrayOfByte1 = new byte[16];
      ((DataInputStream)paramObject).readFully(arrayOfByte1);
      int i = ((DataInputStream)paramObject).readInt();
      byte[] arrayOfByte2 = new byte[lMOtsParameters.getN()];
      ((DataInputStream)paramObject).readFully(arrayOfByte2);
      return new org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey(lMOtsParameters, arrayOfByte1, i, arrayOfByte2);
    } 
    if (paramObject instanceof byte[]) {
      DataInputStream dataInputStream = null;
      try {
        dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[])paramObject));
        return getInstance(dataInputStream);
      } finally {
        if (dataInputStream != null)
          dataInputStream.close(); 
      } 
    } 
    if (paramObject instanceof InputStream)
      return getInstance(Streams.readAll((InputStream)paramObject)); 
    throw new IllegalArgumentException("cannot parse " + paramObject);
  }
  
  public LMOtsParameters getParameter() {
    return this.parameter;
  }
  
  public byte[] getI() {
    return this.I;
  }
  
  public int getQ() {
    return this.q;
  }
  
  public byte[] getK() {
    return this.K;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey lMOtsPublicKey = (org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey)paramObject;
    if (this.q != lMOtsPublicKey.q)
      return false; 
    if ((this.parameter != null) ? !this.parameter.equals(lMOtsPublicKey.parameter) : (lMOtsPublicKey.parameter != null))
      return false; 
    if (!Arrays.equals(this.I, lMOtsPublicKey.I))
      return false; 
    return Arrays.equals(this.K, lMOtsPublicKey.K);
  }
  
  public int hashCode() {
    int i = (this.parameter != null) ? this.parameter.hashCode() : 0;
    i = 31 * i + Arrays.hashCode(this.I);
    i = 31 * i + this.q;
    i = 31 * i + Arrays.hashCode(this.K);
    return i;
  }
  
  public byte[] getEncoded() throws IOException {
    return Composer.compose()
      .u32str(this.parameter.getType())
      .bytes(this.I)
      .u32str(this.q)
      .bytes(this.K).build();
  }
  
  LMSContext createOtsContext(LMOtsSignature paramLMOtsSignature) {
    Digest digest = DigestUtil.getDigest(this.parameter.getDigestOID());
    LmsUtils.byteArray(this.I, digest);
    LmsUtils.u32str(this.q, digest);
    LmsUtils.u16str((short)-32383, digest);
    LmsUtils.byteArray(paramLMOtsSignature.getC(), digest);
    return new LMSContext(this, paramLMOtsSignature, digest);
  }
  
  LMSContext createOtsContext(LMSSignature paramLMSSignature) {
    Digest digest = DigestUtil.getDigest(this.parameter.getDigestOID());
    LmsUtils.byteArray(this.I, digest);
    LmsUtils.u32str(this.q, digest);
    LmsUtils.u16str((short)-32383, digest);
    LmsUtils.byteArray(paramLMSSignature.getOtsSignature().getC(), digest);
    return new LMSContext(this, paramLMSSignature, digest);
  }
}
