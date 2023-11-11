package META-INF.versions.9.org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.util.encoders.Encoder;

public class HexEncoder implements Encoder {
  protected final byte[] encodingTable = new byte[] { 
      48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 
      97, 98, 99, 100, 101, 102 };
  
  protected final byte[] decodingTable = new byte[128];
  
  protected void initialiseDecodingTable() {
    byte b;
    for (b = 0; b < this.decodingTable.length; b++)
      this.decodingTable[b] = -1; 
    for (b = 0; b < this.encodingTable.length; b++)
      this.decodingTable[this.encodingTable[b]] = (byte)b; 
    this.decodingTable[65] = this.decodingTable[97];
    this.decodingTable[66] = this.decodingTable[98];
    this.decodingTable[67] = this.decodingTable[99];
    this.decodingTable[68] = this.decodingTable[100];
    this.decodingTable[69] = this.decodingTable[101];
    this.decodingTable[70] = this.decodingTable[102];
  }
  
  public HexEncoder() {
    initialiseDecodingTable();
  }
  
  public int encode(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws IOException {
    int i = paramInt1;
    int j = paramInt1 + paramInt2;
    int k = paramInt3;
    while (i < j) {
      int m = paramArrayOfbyte1[i++] & 0xFF;
      paramArrayOfbyte2[k++] = this.encodingTable[m >>> 4];
      paramArrayOfbyte2[k++] = this.encodingTable[m & 0xF];
    } 
    return k - paramInt3;
  }
  
  public int getEncodedLength(int paramInt) {
    return paramInt * 2;
  }
  
  public int getMaxDecodedLength(int paramInt) {
    return paramInt / 2;
  }
  
  public int encode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) throws IOException {
    if (paramInt2 < 0)
      return 0; 
    byte[] arrayOfByte = new byte[72];
    int i = paramInt2;
    while (i > 0) {
      int j = Math.min(36, i);
      int k = encode(paramArrayOfbyte, paramInt1, j, arrayOfByte, 0);
      paramOutputStream.write(arrayOfByte, 0, k);
      paramInt1 += j;
      i -= j;
    } 
    return paramInt2 * 2;
  }
  
  private static boolean ignore(char paramChar) {
    return (paramChar == '\n' || paramChar == '\r' || paramChar == '\t' || paramChar == ' ');
  }
  
  public int decode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) throws IOException {
    byte b1 = 0;
    byte[] arrayOfByte = new byte[36];
    byte b2 = 0;
    int i = paramInt1 + paramInt2;
    while (i > paramInt1) {
      if (!ignore((char)paramArrayOfbyte[i - 1]))
        break; 
      i--;
    } 
    int j = paramInt1;
    while (j < i) {
      while (j < i && ignore((char)paramArrayOfbyte[j]))
        j++; 
      byte b3 = this.decodingTable[paramArrayOfbyte[j++]];
      while (j < i && ignore((char)paramArrayOfbyte[j]))
        j++; 
      byte b4 = this.decodingTable[paramArrayOfbyte[j++]];
      if ((b3 | b4) < 0)
        throw new IOException("invalid characters encountered in Hex data"); 
      arrayOfByte[b2++] = (byte)(b3 << 4 | b4);
      if (b2 == arrayOfByte.length) {
        paramOutputStream.write(arrayOfByte);
        b2 = 0;
      } 
      b1++;
    } 
    if (b2 > 0)
      paramOutputStream.write(arrayOfByte, 0, b2); 
    return b1;
  }
  
  public int decode(String paramString, OutputStream paramOutputStream) throws IOException {
    byte b1 = 0;
    byte[] arrayOfByte = new byte[36];
    byte b2 = 0;
    int i = paramString.length();
    while (i > 0) {
      if (!ignore(paramString.charAt(i - 1)))
        break; 
      i--;
    } 
    byte b3 = 0;
    while (b3 < i) {
      while (b3 < i && ignore(paramString.charAt(b3)))
        b3++; 
      byte b4 = this.decodingTable[paramString.charAt(b3++)];
      while (b3 < i && ignore(paramString.charAt(b3)))
        b3++; 
      byte b5 = this.decodingTable[paramString.charAt(b3++)];
      if ((b4 | b5) < 0)
        throw new IOException("invalid characters encountered in Hex string"); 
      arrayOfByte[b2++] = (byte)(b4 << 4 | b5);
      if (b2 == arrayOfByte.length) {
        paramOutputStream.write(arrayOfByte);
        b2 = 0;
      } 
      b1++;
    } 
    if (b2 > 0)
      paramOutputStream.write(arrayOfByte, 0, b2); 
    return b1;
  }
  
  byte[] decodeStrict(String paramString, int paramInt1, int paramInt2) throws IOException {
    if (null == paramString)
      throw new NullPointerException("'str' cannot be null"); 
    if (paramInt1 < 0 || paramInt2 < 0 || paramInt1 > paramString.length() - paramInt2)
      throw new IndexOutOfBoundsException("invalid offset and/or length specified"); 
    if (0 != (paramInt2 & 0x1))
      throw new IOException("a hexadecimal encoding must have an even number of characters"); 
    int i = paramInt2 >>> 1;
    byte[] arrayOfByte = new byte[i];
    int j = paramInt1;
    for (byte b = 0; b < i; b++) {
      byte b1 = this.decodingTable[paramString.charAt(j++)];
      byte b2 = this.decodingTable[paramString.charAt(j++)];
      int k = b1 << 4 | b2;
      if (k < 0)
        throw new IOException("invalid characters encountered in Hex string"); 
      arrayOfByte[b] = (byte)k;
    } 
    return arrayOfByte;
  }
}
