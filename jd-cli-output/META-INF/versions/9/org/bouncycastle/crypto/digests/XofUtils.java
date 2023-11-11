package META-INF.versions.9.org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

public class XofUtils {
  public static byte[] leftEncode(long paramLong) {
    byte b = 1;
    long l = paramLong;
    while ((l >>= 8L) != 0L)
      b = (byte)(b + 1); 
    byte[] arrayOfByte = new byte[b + 1];
    arrayOfByte[0] = b;
    for (byte b1 = 1; b1 <= b; b1++)
      arrayOfByte[b1] = (byte)(int)(paramLong >> 8 * (b - b1)); 
    return arrayOfByte;
  }
  
  public static byte[] rightEncode(long paramLong) {
    byte b = 1;
    long l = paramLong;
    while ((l >>= 8L) != 0L)
      b = (byte)(b + 1); 
    byte[] arrayOfByte = new byte[b + 1];
    arrayOfByte[b] = b;
    for (byte b1 = 0; b1 < b; b1++)
      arrayOfByte[b1] = (byte)(int)(paramLong >> 8 * (b - b1 - 1)); 
    return arrayOfByte;
  }
  
  static byte[] encode(byte paramByte) {
    return Arrays.concatenate(leftEncode(8L), new byte[] { paramByte });
  }
  
  static byte[] encode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (paramArrayOfbyte.length == paramInt2)
      return Arrays.concatenate(leftEncode((paramInt2 * 8)), paramArrayOfbyte); 
    return Arrays.concatenate(leftEncode((paramInt2 * 8)), Arrays.copyOfRange(paramArrayOfbyte, paramInt1, paramInt1 + paramInt2));
  }
}
