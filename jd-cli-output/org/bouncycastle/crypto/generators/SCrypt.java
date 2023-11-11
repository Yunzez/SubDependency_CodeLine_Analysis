package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

public class SCrypt {
  public static byte[] generate(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    if (paramArrayOfbyte1 == null)
      throw new IllegalArgumentException("Passphrase P must be provided."); 
    if (paramArrayOfbyte2 == null)
      throw new IllegalArgumentException("Salt S must be provided."); 
    if (paramInt1 <= 1 || !isPowerOf2(paramInt1))
      throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2"); 
    if (paramInt2 == 1 && paramInt1 >= 65536)
      throw new IllegalArgumentException("Cost parameter N must be > 1 and < 65536."); 
    if (paramInt2 < 1)
      throw new IllegalArgumentException("Block size r must be >= 1."); 
    int i = Integer.MAX_VALUE / 128 * paramInt2 * 8;
    if (paramInt3 < 1 || paramInt3 > i)
      throw new IllegalArgumentException("Parallelisation parameter p must be >= 1 and <= " + i + " (based on block size r of " + paramInt2 + ")"); 
    if (paramInt4 < 1)
      throw new IllegalArgumentException("Generated key length dkLen must be >= 1."); 
    return MFcrypt(paramArrayOfbyte1, paramArrayOfbyte2, paramInt1, paramInt2, paramInt3, paramInt4);
  }
  
  private static byte[] MFcrypt(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    int i = paramInt2 * 128;
    byte[] arrayOfByte = SingleIterationPBKDF2(paramArrayOfbyte1, paramArrayOfbyte2, paramInt3 * i);
    int[] arrayOfInt = null;
    try {
      int j = arrayOfByte.length >>> 2;
      arrayOfInt = new int[j];
      Pack.littleEndianToInt(arrayOfByte, 0, arrayOfInt);
      byte b = 0;
      int k;
      for (k = paramInt1 * paramInt2; paramInt1 - b > 2 && k > 1024; k >>>= 1)
        b++; 
      int m = i >>> 2;
      int n;
      for (n = 0; n < j; n += m)
        SMix(arrayOfInt, n, paramInt1, b, paramInt2); 
      Pack.intToLittleEndian(arrayOfInt, arrayOfByte, 0);
      return SingleIterationPBKDF2(paramArrayOfbyte1, arrayOfByte, paramInt4);
    } finally {
      Clear(arrayOfByte);
      Clear(arrayOfInt);
    } 
  }
  
  private static byte[] SingleIterationPBKDF2(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    PKCS5S2ParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator(new SHA256Digest());
    pKCS5S2ParametersGenerator.init(paramArrayOfbyte1, paramArrayOfbyte2, 1);
    KeyParameter keyParameter = (KeyParameter)pKCS5S2ParametersGenerator.generateDerivedMacParameters(paramInt * 8);
    return keyParameter.getKey();
  }
  
  private static void SMix(int[] paramArrayOfint, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    int i = Integers.numberOfTrailingZeros(paramInt2);
    int j = paramInt2 >>> paramInt3;
    int k = 1 << paramInt3;
    int m = j - 1;
    int n = i - paramInt3;
    int i1 = paramInt4 * 32;
    int[] arrayOfInt1 = new int[16];
    int[] arrayOfInt2 = new int[16];
    int[] arrayOfInt3 = new int[i1];
    int[] arrayOfInt4 = new int[i1];
    int[][] arrayOfInt = new int[k][];
    try {
      System.arraycopy(paramArrayOfint, paramInt1, arrayOfInt4, 0, i1);
      int i2;
      for (i2 = 0; i2 < k; i2++) {
        int[] arrayOfInt5 = new int[j * i1];
        arrayOfInt[i2] = arrayOfInt5;
        int i3 = 0;
        for (byte b1 = 0; b1 < j; b1 += 2) {
          System.arraycopy(arrayOfInt4, 0, arrayOfInt5, i3, i1);
          i3 += i1;
          BlockMix(arrayOfInt4, arrayOfInt1, arrayOfInt2, arrayOfInt3, paramInt4);
          System.arraycopy(arrayOfInt3, 0, arrayOfInt5, i3, i1);
          i3 += i1;
          BlockMix(arrayOfInt3, arrayOfInt1, arrayOfInt2, arrayOfInt4, paramInt4);
        } 
      } 
      i2 = paramInt2 - 1;
      for (byte b = 0; b < paramInt2; b++) {
        int i3 = arrayOfInt4[i1 - 16] & i2;
        int[] arrayOfInt5 = arrayOfInt[i3 >>> n];
        int i4 = (i3 & m) * i1;
        System.arraycopy(arrayOfInt5, i4, arrayOfInt3, 0, i1);
        Xor(arrayOfInt3, arrayOfInt4, 0, arrayOfInt3);
        BlockMix(arrayOfInt3, arrayOfInt1, arrayOfInt2, arrayOfInt4, paramInt4);
      } 
      System.arraycopy(arrayOfInt4, 0, paramArrayOfint, paramInt1, i1);
    } finally {
      ClearAll(arrayOfInt);
      ClearAll(new int[][] { arrayOfInt4, arrayOfInt1, arrayOfInt2, arrayOfInt3 });
    } 
  }
  
  private static void BlockMix(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3, int[] paramArrayOfint4, int paramInt) {
    System.arraycopy(paramArrayOfint1, paramArrayOfint1.length - 16, paramArrayOfint2, 0, 16);
    byte b = 0;
    int i = 0;
    int j = paramArrayOfint1.length >>> 1;
    for (int k = 2 * paramInt; k > 0; k--) {
      Xor(paramArrayOfint2, paramArrayOfint1, b, paramArrayOfint3);
      Salsa20Engine.salsaCore(8, paramArrayOfint3, paramArrayOfint2);
      System.arraycopy(paramArrayOfint2, 0, paramArrayOfint4, i, 16);
      i = j + b - i;
      b += 16;
    } 
  }
  
  private static void Xor(int[] paramArrayOfint1, int[] paramArrayOfint2, int paramInt, int[] paramArrayOfint3) {
    for (int i = paramArrayOfint3.length - 1; i >= 0; i--)
      paramArrayOfint3[i] = paramArrayOfint1[i] ^ paramArrayOfint2[paramInt + i]; 
  }
  
  private static void Clear(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte != null)
      Arrays.fill(paramArrayOfbyte, (byte)0); 
  }
  
  private static void Clear(int[] paramArrayOfint) {
    if (paramArrayOfint != null)
      Arrays.fill(paramArrayOfint, 0); 
  }
  
  private static void ClearAll(int[][] paramArrayOfint) {
    for (byte b = 0; b < paramArrayOfint.length; b++)
      Clear(paramArrayOfint[b]); 
  }
  
  private static boolean isPowerOf2(int paramInt) {
    return ((paramInt & paramInt - 1) == 0);
  }
}
