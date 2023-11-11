package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.util.Encodable;

public class Composer {
  private final ByteArrayOutputStream bos = new ByteArrayOutputStream();
  
  public static org.bouncycastle.pqc.crypto.lms.Composer compose() {
    return new org.bouncycastle.pqc.crypto.lms.Composer();
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer u64str(long paramLong) {
    u32str((int)(paramLong >>> 32L));
    u32str((int)paramLong);
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer u32str(int paramInt) {
    this.bos.write((byte)(paramInt >>> 24));
    this.bos.write((byte)(paramInt >>> 16));
    this.bos.write((byte)(paramInt >>> 8));
    this.bos.write((byte)paramInt);
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer u16str(int paramInt) {
    paramInt &= 0xFFFF;
    this.bos.write((byte)(paramInt >>> 8));
    this.bos.write((byte)paramInt);
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bytes(Encodable[] paramArrayOfEncodable) {
    try {
      for (Encodable encodable : paramArrayOfEncodable)
        this.bos.write(encodable.getEncoded()); 
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bytes(Encodable paramEncodable) {
    try {
      this.bos.write(paramEncodable.getEncoded());
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer pad(int paramInt1, int paramInt2) {
    for (; paramInt2 >= 0; paramInt2--) {
      try {
        this.bos.write(paramInt1);
      } catch (Exception exception) {
        throw new RuntimeException(exception.getMessage(), exception);
      } 
    } 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bytes(byte[][] paramArrayOfbyte) {
    try {
      for (byte[] arrayOfByte : paramArrayOfbyte)
        this.bos.write(arrayOfByte); 
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bytes(byte[][] paramArrayOfbyte, int paramInt1, int paramInt2) {
    try {
      int i = paramInt1;
      while (i != paramInt2) {
        this.bos.write(paramArrayOfbyte[i]);
        i++;
      } 
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bytes(byte[] paramArrayOfbyte) {
    try {
      this.bos.write(paramArrayOfbyte);
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bytes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    try {
      this.bos.write(paramArrayOfbyte, paramInt1, paramInt2);
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
    return this;
  }
  
  public byte[] build() {
    return this.bos.toByteArray();
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer padUntil(int paramInt1, int paramInt2) {
    while (this.bos.size() < paramInt2)
      this.bos.write(paramInt1); 
    return this;
  }
  
  public org.bouncycastle.pqc.crypto.lms.Composer bool(boolean paramBoolean) {
    this.bos.write(paramBoolean ? 1 : 0);
    return this;
  }
}
