package META-INF.versions.9.org.bouncycastle.util;

import java.math.BigInteger;
import org.bouncycastle.util.Objects;

public final class Arrays {
  public static boolean areAllZeroes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = 0;
    for (byte b = 0; b < paramInt2; b++)
      i |= paramArrayOfbyte[paramInt1 + b]; 
    return (i == 0);
  }
  
  public static boolean areEqual(boolean[] paramArrayOfboolean1, boolean[] paramArrayOfboolean2) {
    return java.util.Arrays.equals(paramArrayOfboolean1, paramArrayOfboolean2);
  }
  
  public static boolean areEqual(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    return java.util.Arrays.equals(paramArrayOfbyte1, paramArrayOfbyte2);
  }
  
  public static boolean areEqual(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4) {
    int i = paramInt2 - paramInt1;
    int j = paramInt4 - paramInt3;
    if (i != j)
      return false; 
    for (byte b = 0; b < i; b++) {
      if (paramArrayOfbyte1[paramInt1 + b] != paramArrayOfbyte2[paramInt3 + b])
        return false; 
    } 
    return true;
  }
  
  public static boolean areEqual(char[] paramArrayOfchar1, char[] paramArrayOfchar2) {
    return java.util.Arrays.equals(paramArrayOfchar1, paramArrayOfchar2);
  }
  
  public static boolean areEqual(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    return java.util.Arrays.equals(paramArrayOfint1, paramArrayOfint2);
  }
  
  public static boolean areEqual(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    return java.util.Arrays.equals(paramArrayOflong1, paramArrayOflong2);
  }
  
  public static boolean areEqual(Object[] paramArrayOfObject1, Object[] paramArrayOfObject2) {
    return java.util.Arrays.equals(paramArrayOfObject1, paramArrayOfObject2);
  }
  
  public static boolean areEqual(short[] paramArrayOfshort1, short[] paramArrayOfshort2) {
    return java.util.Arrays.equals(paramArrayOfshort1, paramArrayOfshort2);
  }
  
  public static boolean constantTimeAreEqual(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte1 == null || paramArrayOfbyte2 == null)
      return false; 
    if (paramArrayOfbyte1 == paramArrayOfbyte2)
      return true; 
    int i = (paramArrayOfbyte1.length < paramArrayOfbyte2.length) ? paramArrayOfbyte1.length : paramArrayOfbyte2.length;
    int j = paramArrayOfbyte1.length ^ paramArrayOfbyte2.length;
    int k;
    for (k = 0; k != i; k++)
      j |= paramArrayOfbyte1[k] ^ paramArrayOfbyte2[k]; 
    for (k = i; k < paramArrayOfbyte2.length; k++)
      j |= paramArrayOfbyte2[k] ^ paramArrayOfbyte2[k] ^ 0xFFFFFFFF; 
    return (j == 0);
  }
  
  public static boolean constantTimeAreEqual(int paramInt1, byte[] paramArrayOfbyte1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    if (null == paramArrayOfbyte1)
      throw new NullPointerException("'a' cannot be null"); 
    if (null == paramArrayOfbyte2)
      throw new NullPointerException("'b' cannot be null"); 
    if (paramInt1 < 0)
      throw new IllegalArgumentException("'len' cannot be negative"); 
    if (paramInt2 > paramArrayOfbyte1.length - paramInt1)
      throw new IndexOutOfBoundsException("'aOff' value invalid for specified length"); 
    if (paramInt3 > paramArrayOfbyte2.length - paramInt1)
      throw new IndexOutOfBoundsException("'bOff' value invalid for specified length"); 
    int i = 0;
    for (byte b = 0; b < paramInt1; b++)
      i |= paramArrayOfbyte1[paramInt2 + b] ^ paramArrayOfbyte2[paramInt3 + b]; 
    return (0 == i);
  }
  
  public static int compareUnsigned(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte1 == paramArrayOfbyte2)
      return 0; 
    if (paramArrayOfbyte1 == null)
      return -1; 
    if (paramArrayOfbyte2 == null)
      return 1; 
    int i = Math.min(paramArrayOfbyte1.length, paramArrayOfbyte2.length);
    for (byte b = 0; b < i; b++) {
      int j = paramArrayOfbyte1[b] & 0xFF, k = paramArrayOfbyte2[b] & 0xFF;
      if (j < k)
        return -1; 
      if (j > k)
        return 1; 
    } 
    if (paramArrayOfbyte1.length < paramArrayOfbyte2.length)
      return -1; 
    if (paramArrayOfbyte1.length > paramArrayOfbyte2.length)
      return 1; 
    return 0;
  }
  
  public static boolean contains(boolean[] paramArrayOfboolean, boolean paramBoolean) {
    for (byte b = 0; b < paramArrayOfboolean.length; b++) {
      if (paramArrayOfboolean[b] == paramBoolean)
        return true; 
    } 
    return false;
  }
  
  public static boolean contains(byte[] paramArrayOfbyte, byte paramByte) {
    for (byte b = 0; b < paramArrayOfbyte.length; b++) {
      if (paramArrayOfbyte[b] == paramByte)
        return true; 
    } 
    return false;
  }
  
  public static boolean contains(char[] paramArrayOfchar, char paramChar) {
    for (byte b = 0; b < paramArrayOfchar.length; b++) {
      if (paramArrayOfchar[b] == paramChar)
        return true; 
    } 
    return false;
  }
  
  public static boolean contains(int[] paramArrayOfint, int paramInt) {
    for (byte b = 0; b < paramArrayOfint.length; b++) {
      if (paramArrayOfint[b] == paramInt)
        return true; 
    } 
    return false;
  }
  
  public static boolean contains(long[] paramArrayOflong, long paramLong) {
    for (byte b = 0; b < paramArrayOflong.length; b++) {
      if (paramArrayOflong[b] == paramLong)
        return true; 
    } 
    return false;
  }
  
  public static boolean contains(short[] paramArrayOfshort, short paramShort) {
    for (byte b = 0; b < paramArrayOfshort.length; b++) {
      if (paramArrayOfshort[b] == paramShort)
        return true; 
    } 
    return false;
  }
  
  public static void fill(boolean[] paramArrayOfboolean, boolean paramBoolean) {
    java.util.Arrays.fill(paramArrayOfboolean, paramBoolean);
  }
  
  public static void fill(boolean[] paramArrayOfboolean, int paramInt1, int paramInt2, boolean paramBoolean) {
    java.util.Arrays.fill(paramArrayOfboolean, paramInt1, paramInt2, paramBoolean);
  }
  
  public static void fill(byte[] paramArrayOfbyte, byte paramByte) {
    java.util.Arrays.fill(paramArrayOfbyte, paramByte);
  }
  
  public static void fill(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, byte paramByte) {
    java.util.Arrays.fill(paramArrayOfbyte, paramInt1, paramInt2, paramByte);
  }
  
  public static void fill(char[] paramArrayOfchar, char paramChar) {
    java.util.Arrays.fill(paramArrayOfchar, paramChar);
  }
  
  public static void fill(char[] paramArrayOfchar, int paramInt1, int paramInt2, char paramChar) {
    java.util.Arrays.fill(paramArrayOfchar, paramInt1, paramInt2, paramChar);
  }
  
  public static void fill(int[] paramArrayOfint, int paramInt) {
    java.util.Arrays.fill(paramArrayOfint, paramInt);
  }
  
  public static void fill(int[] paramArrayOfint, int paramInt1, int paramInt2, int paramInt3) {
    java.util.Arrays.fill(paramArrayOfint, paramInt1, paramInt2, paramInt3);
  }
  
  public static void fill(long[] paramArrayOflong, long paramLong) {
    java.util.Arrays.fill(paramArrayOflong, paramLong);
  }
  
  public static void fill(long[] paramArrayOflong, int paramInt1, int paramInt2, long paramLong) {
    java.util.Arrays.fill(paramArrayOflong, paramInt1, paramInt2, paramLong);
  }
  
  public static void fill(Object[] paramArrayOfObject, Object paramObject) {
    java.util.Arrays.fill(paramArrayOfObject, paramObject);
  }
  
  public static void fill(Object[] paramArrayOfObject, int paramInt1, int paramInt2, Object paramObject) {
    java.util.Arrays.fill(paramArrayOfObject, paramInt1, paramInt2, paramObject);
  }
  
  public static void fill(short[] paramArrayOfshort, short paramShort) {
    java.util.Arrays.fill(paramArrayOfshort, paramShort);
  }
  
  public static void fill(short[] paramArrayOfshort, int paramInt1, int paramInt2, short paramShort) {
    java.util.Arrays.fill(paramArrayOfshort, paramInt1, paramInt2, paramShort);
  }
  
  public static int hashCode(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      return 0; 
    int i = paramArrayOfbyte.length;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= paramArrayOfbyte[i];
    } 
    return j;
  }
  
  public static int hashCode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (paramArrayOfbyte == null)
      return 0; 
    int i = paramInt2;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= paramArrayOfbyte[paramInt1 + i];
    } 
    return j;
  }
  
  public static int hashCode(char[] paramArrayOfchar) {
    if (paramArrayOfchar == null)
      return 0; 
    int i = paramArrayOfchar.length;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= paramArrayOfchar[i];
    } 
    return j;
  }
  
  public static int hashCode(int[][] paramArrayOfint) {
    int i = 0;
    for (byte b = 0; b != paramArrayOfint.length; b++)
      i = i * 257 + hashCode(paramArrayOfint[b]); 
    return i;
  }
  
  public static int hashCode(int[] paramArrayOfint) {
    if (paramArrayOfint == null)
      return 0; 
    int i = paramArrayOfint.length;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= paramArrayOfint[i];
    } 
    return j;
  }
  
  public static int hashCode(int[] paramArrayOfint, int paramInt1, int paramInt2) {
    if (paramArrayOfint == null)
      return 0; 
    int i = paramInt2;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= paramArrayOfint[paramInt1 + i];
    } 
    return j;
  }
  
  public static int hashCode(long[] paramArrayOflong) {
    if (paramArrayOflong == null)
      return 0; 
    int i = paramArrayOflong.length;
    int j = i + 1;
    while (--i >= 0) {
      long l = paramArrayOflong[i];
      j *= 257;
      j ^= (int)l;
      j *= 257;
      j ^= (int)(l >>> 32L);
    } 
    return j;
  }
  
  public static int hashCode(long[] paramArrayOflong, int paramInt1, int paramInt2) {
    if (paramArrayOflong == null)
      return 0; 
    int i = paramInt2;
    int j = i + 1;
    while (--i >= 0) {
      long l = paramArrayOflong[paramInt1 + i];
      j *= 257;
      j ^= (int)l;
      j *= 257;
      j ^= (int)(l >>> 32L);
    } 
    return j;
  }
  
  public static int hashCode(short[][][] paramArrayOfshort) {
    int i = 0;
    for (byte b = 0; b != paramArrayOfshort.length; b++)
      i = i * 257 + hashCode(paramArrayOfshort[b]); 
    return i;
  }
  
  public static int hashCode(short[][] paramArrayOfshort) {
    int i = 0;
    for (byte b = 0; b != paramArrayOfshort.length; b++)
      i = i * 257 + hashCode(paramArrayOfshort[b]); 
    return i;
  }
  
  public static int hashCode(short[] paramArrayOfshort) {
    if (paramArrayOfshort == null)
      return 0; 
    int i = paramArrayOfshort.length;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= paramArrayOfshort[i] & 0xFF;
    } 
    return j;
  }
  
  public static int hashCode(Object[] paramArrayOfObject) {
    if (paramArrayOfObject == null)
      return 0; 
    int i = paramArrayOfObject.length;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= Objects.hashCode(paramArrayOfObject[i]);
    } 
    return j;
  }
  
  public static boolean[] clone(boolean[] paramArrayOfboolean) {
    return (null == paramArrayOfboolean) ? null : (boolean[])paramArrayOfboolean.clone();
  }
  
  public static byte[] clone(byte[] paramArrayOfbyte) {
    return (null == paramArrayOfbyte) ? null : (byte[])paramArrayOfbyte.clone();
  }
  
  public static char[] clone(char[] paramArrayOfchar) {
    return (null == paramArrayOfchar) ? null : (char[])paramArrayOfchar.clone();
  }
  
  public static int[] clone(int[] paramArrayOfint) {
    return (null == paramArrayOfint) ? null : (int[])paramArrayOfint.clone();
  }
  
  public static long[] clone(long[] paramArrayOflong) {
    return (null == paramArrayOflong) ? null : (long[])paramArrayOflong.clone();
  }
  
  public static short[] clone(short[] paramArrayOfshort) {
    return (null == paramArrayOfshort) ? null : (short[])paramArrayOfshort.clone();
  }
  
  public static BigInteger[] clone(BigInteger[] paramArrayOfBigInteger) {
    return (null == paramArrayOfBigInteger) ? null : (BigInteger[])paramArrayOfBigInteger.clone();
  }
  
  public static byte[] clone(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte1 == null)
      return null; 
    if (paramArrayOfbyte2 == null || paramArrayOfbyte2.length != paramArrayOfbyte1.length)
      return clone(paramArrayOfbyte1); 
    System.arraycopy(paramArrayOfbyte1, 0, paramArrayOfbyte2, 0, paramArrayOfbyte2.length);
    return paramArrayOfbyte2;
  }
  
  public static long[] clone(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    if (paramArrayOflong1 == null)
      return null; 
    if (paramArrayOflong2 == null || paramArrayOflong2.length != paramArrayOflong1.length)
      return clone(paramArrayOflong1); 
    System.arraycopy(paramArrayOflong1, 0, paramArrayOflong2, 0, paramArrayOflong2.length);
    return paramArrayOflong2;
  }
  
  public static byte[][] clone(byte[][] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      return null; 
    byte[][] arrayOfByte = new byte[paramArrayOfbyte.length][];
    for (byte b = 0; b != arrayOfByte.length; b++)
      arrayOfByte[b] = clone(paramArrayOfbyte[b]); 
    return arrayOfByte;
  }
  
  public static byte[][][] clone(byte[][][] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      return null; 
    byte[][][] arrayOfByte = new byte[paramArrayOfbyte.length][][];
    for (byte b = 0; b != arrayOfByte.length; b++)
      arrayOfByte[b] = clone(paramArrayOfbyte[b]); 
    return arrayOfByte;
  }
  
  public static boolean[] copyOf(boolean[] paramArrayOfboolean, int paramInt) {
    boolean[] arrayOfBoolean = new boolean[paramInt];
    System.arraycopy(paramArrayOfboolean, 0, arrayOfBoolean, 0, Math.min(paramArrayOfboolean.length, paramInt));
    return arrayOfBoolean;
  }
  
  public static byte[] copyOf(byte[] paramArrayOfbyte, int paramInt) {
    byte[] arrayOfByte = new byte[paramInt];
    System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, 0, Math.min(paramArrayOfbyte.length, paramInt));
    return arrayOfByte;
  }
  
  public static char[] copyOf(char[] paramArrayOfchar, int paramInt) {
    char[] arrayOfChar = new char[paramInt];
    System.arraycopy(paramArrayOfchar, 0, arrayOfChar, 0, Math.min(paramArrayOfchar.length, paramInt));
    return arrayOfChar;
  }
  
  public static int[] copyOf(int[] paramArrayOfint, int paramInt) {
    int[] arrayOfInt = new int[paramInt];
    System.arraycopy(paramArrayOfint, 0, arrayOfInt, 0, Math.min(paramArrayOfint.length, paramInt));
    return arrayOfInt;
  }
  
  public static long[] copyOf(long[] paramArrayOflong, int paramInt) {
    long[] arrayOfLong = new long[paramInt];
    System.arraycopy(paramArrayOflong, 0, arrayOfLong, 0, Math.min(paramArrayOflong.length, paramInt));
    return arrayOfLong;
  }
  
  public static short[] copyOf(short[] paramArrayOfshort, int paramInt) {
    short[] arrayOfShort = new short[paramInt];
    System.arraycopy(paramArrayOfshort, 0, arrayOfShort, 0, Math.min(paramArrayOfshort.length, paramInt));
    return arrayOfShort;
  }
  
  public static BigInteger[] copyOf(BigInteger[] paramArrayOfBigInteger, int paramInt) {
    BigInteger[] arrayOfBigInteger = new BigInteger[paramInt];
    System.arraycopy(paramArrayOfBigInteger, 0, arrayOfBigInteger, 0, Math.min(paramArrayOfBigInteger.length, paramInt));
    return arrayOfBigInteger;
  }
  
  public static boolean[] copyOfRange(boolean[] paramArrayOfboolean, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    boolean[] arrayOfBoolean = new boolean[i];
    System.arraycopy(paramArrayOfboolean, paramInt1, arrayOfBoolean, 0, Math.min(paramArrayOfboolean.length - paramInt1, i));
    return arrayOfBoolean;
  }
  
  public static byte[] copyOfRange(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    byte[] arrayOfByte = new byte[i];
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte, 0, Math.min(paramArrayOfbyte.length - paramInt1, i));
    return arrayOfByte;
  }
  
  public static char[] copyOfRange(char[] paramArrayOfchar, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    char[] arrayOfChar = new char[i];
    System.arraycopy(paramArrayOfchar, paramInt1, arrayOfChar, 0, Math.min(paramArrayOfchar.length - paramInt1, i));
    return arrayOfChar;
  }
  
  public static int[] copyOfRange(int[] paramArrayOfint, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    int[] arrayOfInt = new int[i];
    System.arraycopy(paramArrayOfint, paramInt1, arrayOfInt, 0, Math.min(paramArrayOfint.length - paramInt1, i));
    return arrayOfInt;
  }
  
  public static long[] copyOfRange(long[] paramArrayOflong, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    long[] arrayOfLong = new long[i];
    System.arraycopy(paramArrayOflong, paramInt1, arrayOfLong, 0, Math.min(paramArrayOflong.length - paramInt1, i));
    return arrayOfLong;
  }
  
  public static short[] copyOfRange(short[] paramArrayOfshort, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    short[] arrayOfShort = new short[i];
    System.arraycopy(paramArrayOfshort, paramInt1, arrayOfShort, 0, Math.min(paramArrayOfshort.length - paramInt1, i));
    return arrayOfShort;
  }
  
  public static BigInteger[] copyOfRange(BigInteger[] paramArrayOfBigInteger, int paramInt1, int paramInt2) {
    int i = getLength(paramInt1, paramInt2);
    BigInteger[] arrayOfBigInteger = new BigInteger[i];
    System.arraycopy(paramArrayOfBigInteger, paramInt1, arrayOfBigInteger, 0, Math.min(paramArrayOfBigInteger.length - paramInt1, i));
    return arrayOfBigInteger;
  }
  
  private static int getLength(int paramInt1, int paramInt2) {
    int i = paramInt2 - paramInt1;
    if (i < 0) {
      StringBuffer stringBuffer = new StringBuffer(paramInt1);
      stringBuffer.append(" > ").append(paramInt2);
      throw new IllegalArgumentException(stringBuffer.toString());
    } 
    return i;
  }
  
  public static byte[] append(byte[] paramArrayOfbyte, byte paramByte) {
    if (paramArrayOfbyte == null)
      return new byte[] { paramByte }; 
    int i = paramArrayOfbyte.length;
    byte[] arrayOfByte = new byte[i + 1];
    System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, 0, i);
    arrayOfByte[i] = paramByte;
    return arrayOfByte;
  }
  
  public static short[] append(short[] paramArrayOfshort, short paramShort) {
    if (paramArrayOfshort == null)
      return new short[] { paramShort }; 
    int i = paramArrayOfshort.length;
    short[] arrayOfShort = new short[i + 1];
    System.arraycopy(paramArrayOfshort, 0, arrayOfShort, 0, i);
    arrayOfShort[i] = paramShort;
    return arrayOfShort;
  }
  
  public static int[] append(int[] paramArrayOfint, int paramInt) {
    if (paramArrayOfint == null)
      return new int[] { paramInt }; 
    int i = paramArrayOfint.length;
    int[] arrayOfInt = new int[i + 1];
    System.arraycopy(paramArrayOfint, 0, arrayOfInt, 0, i);
    arrayOfInt[i] = paramInt;
    return arrayOfInt;
  }
  
  public static String[] append(String[] paramArrayOfString, String paramString) {
    if (paramArrayOfString == null)
      return new String[] { paramString }; 
    int i = paramArrayOfString.length;
    String[] arrayOfString = new String[i + 1];
    System.arraycopy(paramArrayOfString, 0, arrayOfString, 0, i);
    arrayOfString[i] = paramString;
    return arrayOfString;
  }
  
  public static byte[] concatenate(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (null == paramArrayOfbyte1)
      return clone(paramArrayOfbyte2); 
    if (null == paramArrayOfbyte2)
      return clone(paramArrayOfbyte1); 
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length + paramArrayOfbyte2.length];
    System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte, 0, paramArrayOfbyte1.length);
    System.arraycopy(paramArrayOfbyte2, 0, arrayOfByte, paramArrayOfbyte1.length, paramArrayOfbyte2.length);
    return arrayOfByte;
  }
  
  public static short[] concatenate(short[] paramArrayOfshort1, short[] paramArrayOfshort2) {
    if (null == paramArrayOfshort1)
      return clone(paramArrayOfshort2); 
    if (null == paramArrayOfshort2)
      return clone(paramArrayOfshort1); 
    short[] arrayOfShort = new short[paramArrayOfshort1.length + paramArrayOfshort2.length];
    System.arraycopy(paramArrayOfshort1, 0, arrayOfShort, 0, paramArrayOfshort1.length);
    System.arraycopy(paramArrayOfshort2, 0, arrayOfShort, paramArrayOfshort1.length, paramArrayOfshort2.length);
    return arrayOfShort;
  }
  
  public static byte[] concatenate(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    if (null == paramArrayOfbyte1)
      return concatenate(paramArrayOfbyte2, paramArrayOfbyte3); 
    if (null == paramArrayOfbyte2)
      return concatenate(paramArrayOfbyte1, paramArrayOfbyte3); 
    if (null == paramArrayOfbyte3)
      return concatenate(paramArrayOfbyte1, paramArrayOfbyte2); 
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length + paramArrayOfbyte2.length + paramArrayOfbyte3.length];
    int i = 0;
    System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte, i, paramArrayOfbyte1.length);
    i += paramArrayOfbyte1.length;
    System.arraycopy(paramArrayOfbyte2, 0, arrayOfByte, i, paramArrayOfbyte2.length);
    i += paramArrayOfbyte2.length;
    System.arraycopy(paramArrayOfbyte3, 0, arrayOfByte, i, paramArrayOfbyte3.length);
    return arrayOfByte;
  }
  
  public static byte[] concatenate(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4) {
    if (null == paramArrayOfbyte1)
      return concatenate(paramArrayOfbyte2, paramArrayOfbyte3, paramArrayOfbyte4); 
    if (null == paramArrayOfbyte2)
      return concatenate(paramArrayOfbyte1, paramArrayOfbyte3, paramArrayOfbyte4); 
    if (null == paramArrayOfbyte3)
      return concatenate(paramArrayOfbyte1, paramArrayOfbyte2, paramArrayOfbyte4); 
    if (null == paramArrayOfbyte4)
      return concatenate(paramArrayOfbyte1, paramArrayOfbyte2, paramArrayOfbyte3); 
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length + paramArrayOfbyte2.length + paramArrayOfbyte3.length + paramArrayOfbyte4.length];
    int i = 0;
    System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte, i, paramArrayOfbyte1.length);
    i += paramArrayOfbyte1.length;
    System.arraycopy(paramArrayOfbyte2, 0, arrayOfByte, i, paramArrayOfbyte2.length);
    i += paramArrayOfbyte2.length;
    System.arraycopy(paramArrayOfbyte3, 0, arrayOfByte, i, paramArrayOfbyte3.length);
    i += paramArrayOfbyte3.length;
    System.arraycopy(paramArrayOfbyte4, 0, arrayOfByte, i, paramArrayOfbyte4.length);
    return arrayOfByte;
  }
  
  public static byte[] concatenate(byte[][] paramArrayOfbyte) {
    int i = 0;
    for (byte b1 = 0; b1 != paramArrayOfbyte.length; b1++)
      i += (paramArrayOfbyte[b1]).length; 
    byte[] arrayOfByte = new byte[i];
    int j = 0;
    for (byte b2 = 0; b2 != paramArrayOfbyte.length; b2++) {
      System.arraycopy(paramArrayOfbyte[b2], 0, arrayOfByte, j, (paramArrayOfbyte[b2]).length);
      j += (paramArrayOfbyte[b2]).length;
    } 
    return arrayOfByte;
  }
  
  public static int[] concatenate(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    if (null == paramArrayOfint1)
      return clone(paramArrayOfint2); 
    if (null == paramArrayOfint2)
      return clone(paramArrayOfint1); 
    int[] arrayOfInt = new int[paramArrayOfint1.length + paramArrayOfint2.length];
    System.arraycopy(paramArrayOfint1, 0, arrayOfInt, 0, paramArrayOfint1.length);
    System.arraycopy(paramArrayOfint2, 0, arrayOfInt, paramArrayOfint1.length, paramArrayOfint2.length);
    return arrayOfInt;
  }
  
  public static byte[] prepend(byte[] paramArrayOfbyte, byte paramByte) {
    if (paramArrayOfbyte == null)
      return new byte[] { paramByte }; 
    int i = paramArrayOfbyte.length;
    byte[] arrayOfByte = new byte[i + 1];
    System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, 1, i);
    arrayOfByte[0] = paramByte;
    return arrayOfByte;
  }
  
  public static short[] prepend(short[] paramArrayOfshort, short paramShort) {
    if (paramArrayOfshort == null)
      return new short[] { paramShort }; 
    int i = paramArrayOfshort.length;
    short[] arrayOfShort = new short[i + 1];
    System.arraycopy(paramArrayOfshort, 0, arrayOfShort, 1, i);
    arrayOfShort[0] = paramShort;
    return arrayOfShort;
  }
  
  public static int[] prepend(int[] paramArrayOfint, int paramInt) {
    if (paramArrayOfint == null)
      return new int[] { paramInt }; 
    int i = paramArrayOfint.length;
    int[] arrayOfInt = new int[i + 1];
    System.arraycopy(paramArrayOfint, 0, arrayOfInt, 1, i);
    arrayOfInt[0] = paramInt;
    return arrayOfInt;
  }
  
  public static byte[] reverse(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      return null; 
    byte b = 0;
    int i = paramArrayOfbyte.length;
    byte[] arrayOfByte = new byte[i];
    while (--i >= 0)
      arrayOfByte[i] = paramArrayOfbyte[b++]; 
    return arrayOfByte;
  }
  
  public static int[] reverse(int[] paramArrayOfint) {
    if (paramArrayOfint == null)
      return null; 
    byte b = 0;
    int i = paramArrayOfint.length;
    int[] arrayOfInt = new int[i];
    while (--i >= 0)
      arrayOfInt[i] = paramArrayOfint[b++]; 
    return arrayOfInt;
  }
  
  public static byte[] reverseInPlace(byte[] paramArrayOfbyte) {
    if (null == paramArrayOfbyte)
      return null; 
    byte b = 0;
    int i = paramArrayOfbyte.length - 1;
    while (b < i) {
      byte b1 = paramArrayOfbyte[b], b2 = paramArrayOfbyte[i];
      paramArrayOfbyte[b++] = b2;
      paramArrayOfbyte[i--] = b1;
    } 
    return paramArrayOfbyte;
  }
  
  public static int[] reverseInPlace(int[] paramArrayOfint) {
    if (null == paramArrayOfint)
      return null; 
    byte b = 0;
    int i = paramArrayOfint.length - 1;
    while (b < i) {
      int j = paramArrayOfint[b], k = paramArrayOfint[i];
      paramArrayOfint[b++] = k;
      paramArrayOfint[i--] = j;
    } 
    return paramArrayOfint;
  }
  
  public static void clear(byte[] paramArrayOfbyte) {
    if (null != paramArrayOfbyte)
      java.util.Arrays.fill(paramArrayOfbyte, (byte)0); 
  }
  
  public static void clear(int[] paramArrayOfint) {
    if (null != paramArrayOfint)
      java.util.Arrays.fill(paramArrayOfint, 0); 
  }
  
  public static boolean isNullOrContainsNull(Object[] paramArrayOfObject) {
    if (null == paramArrayOfObject)
      return true; 
    int i = paramArrayOfObject.length;
    for (byte b = 0; b < i; b++) {
      if (null == paramArrayOfObject[b])
        return true; 
    } 
    return false;
  }
  
  public static boolean isNullOrEmpty(byte[] paramArrayOfbyte) {
    return (null == paramArrayOfbyte || paramArrayOfbyte.length < 1);
  }
  
  public static boolean isNullOrEmpty(int[] paramArrayOfint) {
    return (null == paramArrayOfint || paramArrayOfint.length < 1);
  }
  
  public static boolean isNullOrEmpty(Object[] paramArrayOfObject) {
    return (null == paramArrayOfObject || paramArrayOfObject.length < 1);
  }
}
