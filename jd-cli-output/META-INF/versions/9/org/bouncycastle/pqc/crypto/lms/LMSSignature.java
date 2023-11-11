package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.LMOtsSignature;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

class LMSSignature implements Encodable {
  private final int q;
  
  private final LMOtsSignature otsSignature;
  
  private final LMSigParameters parameter;
  
  private final byte[][] y;
  
  public LMSSignature(int paramInt, LMOtsSignature paramLMOtsSignature, LMSigParameters paramLMSigParameters, byte[][] paramArrayOfbyte) {
    this.q = paramInt;
    this.otsSignature = paramLMOtsSignature;
    this.parameter = paramLMSigParameters;
    this.y = paramArrayOfbyte;
  }
  
  public static org.bouncycastle.pqc.crypto.lms.LMSSignature getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof org.bouncycastle.pqc.crypto.lms.LMSSignature)
      return (org.bouncycastle.pqc.crypto.lms.LMSSignature)paramObject; 
    if (paramObject instanceof DataInputStream) {
      int i = ((DataInputStream)paramObject).readInt();
      LMOtsSignature lMOtsSignature = LMOtsSignature.getInstance(paramObject);
      LMSigParameters lMSigParameters = LMSigParameters.getParametersForType(((DataInputStream)paramObject).readInt());
      byte[][] arrayOfByte = new byte[lMSigParameters.getH()][];
      for (byte b = 0; b < arrayOfByte.length; b++) {
        arrayOfByte[b] = new byte[lMSigParameters.getM()];
        ((DataInputStream)paramObject).readFully(arrayOfByte[b]);
      } 
      return new org.bouncycastle.pqc.crypto.lms.LMSSignature(i, lMOtsSignature, lMSigParameters, arrayOfByte);
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
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    org.bouncycastle.pqc.crypto.lms.LMSSignature lMSSignature = (org.bouncycastle.pqc.crypto.lms.LMSSignature)paramObject;
    if (this.q != lMSSignature.q)
      return false; 
    if ((this.otsSignature != null) ? !this.otsSignature.equals(lMSSignature.otsSignature) : (lMSSignature.otsSignature != null))
      return false; 
    if ((this.parameter != null) ? !this.parameter.equals(lMSSignature.parameter) : (lMSSignature.parameter != null))
      return false; 
    return Arrays.deepEquals((Object[])this.y, (Object[])lMSSignature.y);
  }
  
  public int hashCode() {
    int i = this.q;
    i = 31 * i + ((this.otsSignature != null) ? this.otsSignature.hashCode() : 0);
    i = 31 * i + ((this.parameter != null) ? this.parameter.hashCode() : 0);
    i = 31 * i + Arrays.deepHashCode((Object[])this.y);
    return i;
  }
  
  public byte[] getEncoded() throws IOException {
    return Composer.compose()
      .u32str(this.q)
      .bytes(this.otsSignature.getEncoded())
      .u32str(this.parameter.getType())
      .bytes(this.y)
      .build();
  }
  
  public int getQ() {
    return this.q;
  }
  
  public LMOtsSignature getOtsSignature() {
    return this.otsSignature;
  }
  
  public LMSigParameters getParameter() {
    return this.parameter;
  }
  
  public byte[][] getY() {
    return this.y;
  }
}
