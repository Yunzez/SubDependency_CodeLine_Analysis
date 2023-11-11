package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;

public class NullDigest implements Digest {
  private OpenByteArrayOutputStream bOut = new OpenByteArrayOutputStream();
  
  public String getAlgorithmName() {
    return "NULL";
  }
  
  public int getDigestSize() {
    return this.bOut.size();
  }
  
  public void update(byte paramByte) {
    this.bOut.write(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.bOut.write(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    int i = this.bOut.size();
    this.bOut.copy(paramArrayOfbyte, paramInt);
    reset();
    return i;
  }
  
  public void reset() {
    this.bOut.reset();
  }
  
  private static class OpenByteArrayOutputStream extends ByteArrayOutputStream {
    private OpenByteArrayOutputStream() {}
    
    public void reset() {
      super.reset();
      Arrays.clear(this.buf);
    }
    
    void copy(byte[] param1ArrayOfbyte, int param1Int) {
      System.arraycopy(this.buf, 0, param1ArrayOfbyte, param1Int, size());
    }
  }
}
