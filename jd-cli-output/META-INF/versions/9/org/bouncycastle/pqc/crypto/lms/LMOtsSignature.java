package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

class LMOtsSignature implements Encodable {
  private final LMOtsParameters type;
  
  private final byte[] C;
  
  private final byte[] y;
  
  public LMOtsSignature(LMOtsParameters paramLMOtsParameters, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.type = paramLMOtsParameters;
    this.C = paramArrayOfbyte1;
    this.y = paramArrayOfbyte2;
  }
  
  public static org.bouncycastle.pqc.crypto.lms.LMOtsSignature getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof org.bouncycastle.pqc.crypto.lms.LMOtsSignature)
      return (org.bouncycastle.pqc.crypto.lms.LMOtsSignature)paramObject; 
    if (paramObject instanceof DataInputStream) {
      LMOtsParameters lMOtsParameters = LMOtsParameters.getParametersForType(((DataInputStream)paramObject).readInt());
      byte[] arrayOfByte1 = new byte[lMOtsParameters.getN()];
      ((DataInputStream)paramObject).readFully(arrayOfByte1);
      byte[] arrayOfByte2 = new byte[lMOtsParameters.getP() * lMOtsParameters.getN()];
      ((DataInputStream)paramObject).readFully(arrayOfByte2);
      return new org.bouncycastle.pqc.crypto.lms.LMOtsSignature(lMOtsParameters, arrayOfByte1, arrayOfByte2);
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
  
  public LMOtsParameters getType() {
    return this.type;
  }
  
  public byte[] getC() {
    return this.C;
  }
  
  public byte[] getY() {
    return this.y;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    org.bouncycastle.pqc.crypto.lms.LMOtsSignature lMOtsSignature = (org.bouncycastle.pqc.crypto.lms.LMOtsSignature)paramObject;
    if ((this.type != null) ? !this.type.equals(lMOtsSignature.type) : (lMOtsSignature.type != null))
      return false; 
    if (!Arrays.equals(this.C, lMOtsSignature.C))
      return false; 
    return Arrays.equals(this.y, lMOtsSignature.y);
  }
  
  public int hashCode() {
    int i = (this.type != null) ? this.type.hashCode() : 0;
    i = 31 * i + Arrays.hashCode(this.C);
    i = 31 * i + Arrays.hashCode(this.y);
    return i;
  }
  
  public byte[] getEncoded() throws IOException {
    return Composer.compose()
      .u32str(this.type.getType())
      .bytes(this.C)
      .bytes(this.y)
      .build();
  }
}
