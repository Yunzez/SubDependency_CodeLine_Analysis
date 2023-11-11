package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

public class Base64Encoder implements Encoder {
  protected final byte[] encodingTable = new byte[] { 
      65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 
      75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 
      85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 
      101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 
      111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 
      121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 
      56, 57, 43, 47 };
  
  protected byte padding = 61;
  
  protected final byte[] decodingTable = new byte[128];
  
  protected void initialiseDecodingTable() {
    byte b;
    for (b = 0; b < this.decodingTable.length; b++)
      this.decodingTable[b] = -1; 
    for (b = 0; b < this.encodingTable.length; b++)
      this.decodingTable[this.encodingTable[b]] = (byte)b; 
  }
  
  public Base64Encoder() {
    initialiseDecodingTable();
  }
  
  public int encode(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws IOException {
    int m;
    int n;
    int i = paramInt1;
    int j = paramInt1 + paramInt2 - 2;
    int k = paramInt3;
    while (i < j) {
      byte b = paramArrayOfbyte1[i++];
      int i1 = paramArrayOfbyte1[i++] & 0xFF;
      int i2 = paramArrayOfbyte1[i++] & 0xFF;
      paramArrayOfbyte2[k++] = this.encodingTable[b >>> 2 & 0x3F];
      paramArrayOfbyte2[k++] = this.encodingTable[(b << 4 | i1 >>> 4) & 0x3F];
      paramArrayOfbyte2[k++] = this.encodingTable[(i1 << 2 | i2 >>> 6) & 0x3F];
      paramArrayOfbyte2[k++] = this.encodingTable[i2 & 0x3F];
    } 
    switch (paramInt2 - i - paramInt1) {
      case 1:
        m = paramArrayOfbyte1[i++] & 0xFF;
        paramArrayOfbyte2[k++] = this.encodingTable[m >>> 2 & 0x3F];
        paramArrayOfbyte2[k++] = this.encodingTable[m << 4 & 0x3F];
        paramArrayOfbyte2[k++] = this.padding;
        paramArrayOfbyte2[k++] = this.padding;
        break;
      case 2:
        m = paramArrayOfbyte1[i++] & 0xFF;
        n = paramArrayOfbyte1[i++] & 0xFF;
        paramArrayOfbyte2[k++] = this.encodingTable[m >>> 2 & 0x3F];
        paramArrayOfbyte2[k++] = this.encodingTable[(m << 4 | n >>> 4) & 0x3F];
        paramArrayOfbyte2[k++] = this.encodingTable[n << 2 & 0x3F];
        paramArrayOfbyte2[k++] = this.padding;
        break;
    } 
    return k - paramInt3;
  }
  
  public int getEncodedLength(int paramInt) {
    return (paramInt + 2) / 3 * 4;
  }
  
  public int getMaxDecodedLength(int paramInt) {
    return paramInt / 4 * 3;
  }
  
  public int encode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) throws IOException {
    if (paramInt2 < 0)
      return 0; 
    byte[] arrayOfByte = new byte[72];
    int i;
    for (i = paramInt2; i > 0; i -= j) {
      int j = Math.min(54, i);
      int k = encode(paramArrayOfbyte, paramInt1, j, arrayOfByte, 0);
      paramOutputStream.write(arrayOfByte, 0, k);
      paramInt1 += j;
    } 
    return (paramInt2 + 2) / 3 * 4;
  }
  
  private boolean ignore(char paramChar) {
    return (paramChar == '\n' || paramChar == '\r' || paramChar == '\t' || paramChar == ' ');
  }
  
  public int decode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) throws IOException {
    byte[] arrayOfByte = new byte[54];
    byte b = 0;
    int i = 0;
    int j;
    for (j = paramInt1 + paramInt2; j > paramInt1 && ignore((char)paramArrayOfbyte[j - 1]); j--);
    if (j == 0)
      return 0; 
    int k = 0;
    int m;
    for (m = j; m > paramInt1 && k != 4; m--) {
      if (!ignore((char)paramArrayOfbyte[m - 1]))
        k++; 
    } 
    for (k = nextI(paramArrayOfbyte, paramInt1, m); k < m; k = nextI(paramArrayOfbyte, k, m)) {
      byte b1 = this.decodingTable[paramArrayOfbyte[k++]];
      k = nextI(paramArrayOfbyte, k, m);
      byte b2 = this.decodingTable[paramArrayOfbyte[k++]];
      k = nextI(paramArrayOfbyte, k, m);
      byte b3 = this.decodingTable[paramArrayOfbyte[k++]];
      k = nextI(paramArrayOfbyte, k, m);
      byte b4 = this.decodingTable[paramArrayOfbyte[k++]];
      if ((b1 | b2 | b3 | b4) < 0)
        throw new IOException("invalid characters encountered in base64 data"); 
      arrayOfByte[b++] = (byte)(b1 << 2 | b2 >> 4);
      arrayOfByte[b++] = (byte)(b2 << 4 | b3 >> 2);
      arrayOfByte[b++] = (byte)(b3 << 6 | b4);
      if (b == arrayOfByte.length) {
        paramOutputStream.write(arrayOfByte);
        b = 0;
      } 
      i += true;
    } 
    if (b > 0)
      paramOutputStream.write(arrayOfByte, 0, b); 
    int n = nextI(paramArrayOfbyte, k, j);
    int i1 = nextI(paramArrayOfbyte, n + 1, j);
    int i2 = nextI(paramArrayOfbyte, i1 + 1, j);
    int i3 = nextI(paramArrayOfbyte, i2 + 1, j);
    i += decodeLastBlock(paramOutputStream, (char)paramArrayOfbyte[n], (char)paramArrayOfbyte[i1], (char)paramArrayOfbyte[i2], (char)paramArrayOfbyte[i3]);
    return i;
  }
  
  private int nextI(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    while (paramInt1 < paramInt2 && ignore((char)paramArrayOfbyte[paramInt1]))
      paramInt1++; 
    return paramInt1;
  }
  
  public int decode(String paramString, OutputStream paramOutputStream) throws IOException {
    byte[] arrayOfByte = new byte[54];
    byte b = 0;
    int i = 0;
    int j;
    for (j = paramString.length(); j > 0 && ignore(paramString.charAt(j - 1)); j--);
    if (j == 0)
      return 0; 
    int k = 0;
    int m;
    for (m = j; m > 0 && k != 4; m--) {
      if (!ignore(paramString.charAt(m - 1)))
        k++; 
    } 
    for (k = nextI(paramString, 0, m); k < m; k = nextI(paramString, k, m)) {
      byte b1 = this.decodingTable[paramString.charAt(k++)];
      k = nextI(paramString, k, m);
      byte b2 = this.decodingTable[paramString.charAt(k++)];
      k = nextI(paramString, k, m);
      byte b3 = this.decodingTable[paramString.charAt(k++)];
      k = nextI(paramString, k, m);
      byte b4 = this.decodingTable[paramString.charAt(k++)];
      if ((b1 | b2 | b3 | b4) < 0)
        throw new IOException("invalid characters encountered in base64 data"); 
      arrayOfByte[b++] = (byte)(b1 << 2 | b2 >> 4);
      arrayOfByte[b++] = (byte)(b2 << 4 | b3 >> 2);
      arrayOfByte[b++] = (byte)(b3 << 6 | b4);
      i += true;
      if (b == arrayOfByte.length) {
        paramOutputStream.write(arrayOfByte);
        b = 0;
      } 
    } 
    if (b > 0)
      paramOutputStream.write(arrayOfByte, 0, b); 
    int n = nextI(paramString, k, j);
    int i1 = nextI(paramString, n + 1, j);
    int i2 = nextI(paramString, i1 + 1, j);
    int i3 = nextI(paramString, i2 + 1, j);
    i += decodeLastBlock(paramOutputStream, paramString.charAt(n), paramString.charAt(i1), paramString.charAt(i2), paramString.charAt(i3));
    return i;
  }
  
  private int decodeLastBlock(OutputStream paramOutputStream, char paramChar1, char paramChar2, char paramChar3, char paramChar4) throws IOException {
    if (paramChar3 == this.padding) {
      if (paramChar4 != this.padding)
        throw new IOException("invalid characters encountered at end of base64 data"); 
      byte b5 = this.decodingTable[paramChar1];
      byte b6 = this.decodingTable[paramChar2];
      if ((b5 | b6) < 0)
        throw new IOException("invalid characters encountered at end of base64 data"); 
      paramOutputStream.write(b5 << 2 | b6 >> 4);
      return 1;
    } 
    if (paramChar4 == this.padding) {
      byte b5 = this.decodingTable[paramChar1];
      byte b6 = this.decodingTable[paramChar2];
      byte b7 = this.decodingTable[paramChar3];
      if ((b5 | b6 | b7) < 0)
        throw new IOException("invalid characters encountered at end of base64 data"); 
      paramOutputStream.write(b5 << 2 | b6 >> 4);
      paramOutputStream.write(b6 << 4 | b7 >> 2);
      return 2;
    } 
    byte b1 = this.decodingTable[paramChar1];
    byte b2 = this.decodingTable[paramChar2];
    byte b3 = this.decodingTable[paramChar3];
    byte b4 = this.decodingTable[paramChar4];
    if ((b1 | b2 | b3 | b4) < 0)
      throw new IOException("invalid characters encountered at end of base64 data"); 
    paramOutputStream.write(b1 << 2 | b2 >> 4);
    paramOutputStream.write(b2 << 4 | b3 >> 2);
    paramOutputStream.write(b3 << 6 | b4);
    return 3;
  }
  
  private int nextI(String paramString, int paramInt1, int paramInt2) {
    while (paramInt1 < paramInt2 && ignore(paramString.charAt(paramInt1)))
      paramInt1++; 
    return paramInt1;
  }
}
