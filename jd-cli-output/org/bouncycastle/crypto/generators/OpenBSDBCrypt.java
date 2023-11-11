package org.bouncycastle.crypto.generators;

import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class OpenBSDBCrypt {
  private static final byte[] encodingTable = new byte[] { 
      46, 47, 65, 66, 67, 68, 69, 70, 71, 72, 
      73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 
      83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 
      99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 
      109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 
      119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 
      54, 55, 56, 57 };
  
  private static final byte[] decodingTable = new byte[128];
  
  private static final String defaultVersion = "2y";
  
  private static final Set<String> allowedVersions = new HashSet<String>();
  
  public static String generate(char[] paramArrayOfchar, byte[] paramArrayOfbyte, int paramInt) {
    return generate("2y", paramArrayOfchar, paramArrayOfbyte, paramInt);
  }
  
  public static String generate(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    return generate("2y", paramArrayOfbyte1, paramArrayOfbyte2, paramInt);
  }
  
  public static String generate(String paramString, char[] paramArrayOfchar, byte[] paramArrayOfbyte, int paramInt) {
    if (paramArrayOfchar == null)
      throw new IllegalArgumentException("Password required."); 
    return doGenerate(paramString, Strings.toUTF8ByteArray(paramArrayOfchar), paramArrayOfbyte, paramInt);
  }
  
  public static String generate(String paramString, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    if (paramArrayOfbyte1 == null)
      throw new IllegalArgumentException("Password required."); 
    return doGenerate(paramString, Arrays.clone(paramArrayOfbyte1), paramArrayOfbyte2, paramInt);
  }
  
  private static String doGenerate(String paramString, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    if (!allowedVersions.contains(paramString))
      throw new IllegalArgumentException("Version " + paramString + " is not accepted by this implementation."); 
    if (paramArrayOfbyte2 == null)
      throw new IllegalArgumentException("Salt required."); 
    if (paramArrayOfbyte2.length != 16)
      throw new DataLengthException("16 byte salt required: " + paramArrayOfbyte2.length); 
    if (paramInt < 4 || paramInt > 31)
      throw new IllegalArgumentException("Invalid cost factor."); 
    byte[] arrayOfByte = new byte[(paramArrayOfbyte1.length >= 72) ? 72 : (paramArrayOfbyte1.length + 1)];
    if (arrayOfByte.length > paramArrayOfbyte1.length) {
      System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte, 0, paramArrayOfbyte1.length);
    } else {
      System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte, 0, arrayOfByte.length);
    } 
    Arrays.fill(paramArrayOfbyte1, (byte)0);
    String str = createBcryptString(paramString, arrayOfByte, paramArrayOfbyte2, paramInt);
    Arrays.fill(arrayOfByte, (byte)0);
    return str;
  }
  
  public static boolean checkPassword(String paramString, char[] paramArrayOfchar) {
    if (paramArrayOfchar == null)
      throw new IllegalArgumentException("Missing password."); 
    return doCheckPassword(paramString, Strings.toUTF8ByteArray(paramArrayOfchar));
  }
  
  public static boolean checkPassword(String paramString, byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      throw new IllegalArgumentException("Missing password."); 
    return doCheckPassword(paramString, Arrays.clone(paramArrayOfbyte));
  }
  
  private static boolean doCheckPassword(String paramString, byte[] paramArrayOfbyte) {
    String str1;
    byte b;
    if (paramString == null)
      throw new IllegalArgumentException("Missing bcryptString."); 
    if (paramString.charAt(1) != '2')
      throw new IllegalArgumentException("not a Bcrypt string"); 
    int i = paramString.length();
    if (i != 60 && (i != 59 || paramString.charAt(2) != '$'))
      throw new DataLengthException("Bcrypt String length: " + i + ", 60 required."); 
    if (paramString.charAt(2) == '$') {
      if (paramString.charAt(0) != '$' || paramString.charAt(5) != '$')
        throw new IllegalArgumentException("Invalid Bcrypt String format."); 
    } else if (paramString.charAt(0) != '$' || paramString.charAt(3) != '$' || paramString.charAt(6) != '$') {
      throw new IllegalArgumentException("Invalid Bcrypt String format.");
    } 
    if (paramString.charAt(2) == '$') {
      str1 = paramString.substring(1, 2);
      b = 3;
    } else {
      str1 = paramString.substring(1, 3);
      b = 4;
    } 
    if (!allowedVersions.contains(str1))
      throw new IllegalArgumentException("Bcrypt version '" + str1 + "' is not supported by this implementation"); 
    int j = 0;
    String str2 = paramString.substring(b, b + 2);
    try {
      j = Integer.parseInt(str2);
    } catch (NumberFormatException numberFormatException) {
      throw new IllegalArgumentException("Invalid cost factor: " + str2);
    } 
    if (j < 4 || j > 31)
      throw new IllegalArgumentException("Invalid cost factor: " + j + ", 4 < cost < 31 expected."); 
    byte[] arrayOfByte = decodeSaltString(paramString.substring(paramString.lastIndexOf('$') + 1, i - 31));
    String str3 = doGenerate(str1, paramArrayOfbyte, arrayOfByte, j);
    return Strings.constantTimeAreEqual(paramString, str3);
  }
  
  private static String createBcryptString(String paramString, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    if (!allowedVersions.contains(paramString))
      throw new IllegalArgumentException("Version " + paramString + " is not accepted by this implementation."); 
    StringBuilder stringBuilder = new StringBuilder(60);
    stringBuilder.append('$');
    stringBuilder.append(paramString);
    stringBuilder.append('$');
    stringBuilder.append((paramInt < 10) ? ("0" + paramInt) : Integer.toString(paramInt));
    stringBuilder.append('$');
    encodeData(stringBuilder, paramArrayOfbyte2);
    byte[] arrayOfByte = BCrypt.generate(paramArrayOfbyte1, paramArrayOfbyte2, paramInt);
    encodeData(stringBuilder, arrayOfByte);
    return stringBuilder.toString();
  }
  
  private static void encodeData(StringBuilder paramStringBuilder, byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length != 24 && paramArrayOfbyte.length != 16)
      throw new DataLengthException("Invalid length: " + paramArrayOfbyte.length + ", 24 for key or 16 for salt expected"); 
    boolean bool = false;
    if (paramArrayOfbyte.length == 16) {
      bool = true;
      byte[] arrayOfByte = new byte[18];
      System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, 0, paramArrayOfbyte.length);
      paramArrayOfbyte = arrayOfByte;
    } else {
      paramArrayOfbyte[paramArrayOfbyte.length - 1] = 0;
    } 
    int i = paramArrayOfbyte.length;
    for (byte b = 0; b < i; b += 3) {
      int j = paramArrayOfbyte[b] & 0xFF;
      int k = paramArrayOfbyte[b + 1] & 0xFF;
      int m = paramArrayOfbyte[b + 2] & 0xFF;
      paramStringBuilder.append((char)encodingTable[j >>> 2 & 0x3F]);
      paramStringBuilder.append((char)encodingTable[(j << 4 | k >>> 4) & 0x3F]);
      paramStringBuilder.append((char)encodingTable[(k << 2 | m >>> 6) & 0x3F]);
      paramStringBuilder.append((char)encodingTable[m & 0x3F]);
    } 
    if (bool == true) {
      paramStringBuilder.setLength(paramStringBuilder.length() - 2);
    } else {
      paramStringBuilder.setLength(paramStringBuilder.length() - 1);
    } 
  }
  
  private static byte[] decodeSaltString(String paramString) {
    char[] arrayOfChar1 = paramString.toCharArray();
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(16);
    if (arrayOfChar1.length != 22)
      throw new DataLengthException("Invalid base64 salt length: " + arrayOfChar1.length + " , 22 required."); 
    for (byte b1 = 0; b1 < arrayOfChar1.length; b1++) {
      char c = arrayOfChar1[b1];
      if (c > 'z' || c < '.' || (c > '9' && c < 'A'))
        throw new IllegalArgumentException("Salt string contains invalid character: " + c); 
    } 
    char[] arrayOfChar2 = new char[24];
    System.arraycopy(arrayOfChar1, 0, arrayOfChar2, 0, arrayOfChar1.length);
    arrayOfChar1 = arrayOfChar2;
    int i = arrayOfChar1.length;
    for (byte b2 = 0; b2 < i; b2 += 4) {
      byte b3 = decodingTable[arrayOfChar1[b2]];
      byte b4 = decodingTable[arrayOfChar1[b2 + 1]];
      byte b5 = decodingTable[arrayOfChar1[b2 + 2]];
      byte b6 = decodingTable[arrayOfChar1[b2 + 3]];
      byteArrayOutputStream.write(b3 << 2 | b4 >> 4);
      byteArrayOutputStream.write(b4 << 4 | b5 >> 2);
      byteArrayOutputStream.write(b5 << 6 | b6);
    } 
    null = byteArrayOutputStream.toByteArray();
    byte[] arrayOfByte = new byte[16];
    System.arraycopy(null, 0, arrayOfByte, 0, arrayOfByte.length);
    return arrayOfByte;
  }
  
  static {
    allowedVersions.add("2");
    allowedVersions.add("2x");
    allowedVersions.add("2a");
    allowedVersions.add("2y");
    allowedVersions.add("2b");
    byte b;
    for (b = 0; b < decodingTable.length; b++)
      decodingTable[b] = -1; 
    for (b = 0; b < encodingTable.length; b++)
      decodingTable[encodingTable[b]] = (byte)b; 
  }
}
