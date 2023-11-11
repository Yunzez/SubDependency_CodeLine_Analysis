package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
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
  
  public static LMOtsSignature getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof LMOtsSignature)
      return (LMOtsSignature)paramObject; 
    if (paramObject instanceof DataInputStream) {
      LMOtsParameters lMOtsParameters = LMOtsParameters.getParametersForType(((DataInputStream)paramObject).readInt());
      byte[] arrayOfByte1 = new byte[lMOtsParameters.getN()];
      ((DataInputStream)paramObject).readFully(arrayOfByte1);
      byte[] arrayOfByte2 = new byte[lMOtsParameters.getP() * lMOtsParameters.getN()];
      ((DataInputStream)paramObject).readFully(arrayOfByte2);
      return new LMOtsSignature(lMOtsParameters, arrayOfByte1, arrayOfByte2);
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
    LMOtsSignature lMOtsSignature = (LMOtsSignature)paramObject;
    return ((this.type != null) ? !this.type.equals(lMOtsSignature.type) : (lMOtsSignature.type != null)) ? false : (!Arrays.equals(this.C, lMOtsSignature.C) ? false : Arrays.equals(this.y, lMOtsSignature.y));
  }
  
  public int hashCode() {
    null = (this.type != null) ? this.type.hashCode() : 0;
    null = 31 * null + Arrays.hashCode(this.C);
    return 31 * null + Arrays.hashCode(this.y);
  }
  
  public byte[] getEncoded() throws IOException {
    return Composer.compose().u32str(this.type.getType()).bytes(this.C).bytes(this.y).build();
  }
}
