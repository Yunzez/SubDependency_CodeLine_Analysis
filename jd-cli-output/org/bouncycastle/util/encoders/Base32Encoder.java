package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class Base32Encoder implements Encoder {
  private static final byte[] DEAULT_ENCODING_TABLE = new byte[] { 
      65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 
      75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 
      85, 86, 87, 88, 89, 90, 50, 51, 52, 53, 
      54, 55 };
  
  private static final byte DEFAULT_PADDING = 61;
  
  private final byte[] encodingTable;
  
  private final byte padding;
  
  private final byte[] decodingTable = new byte[128];
  
  protected void initialiseDecodingTable() {
    byte b;
    for (b = 0; b < this.decodingTable.length; b++)
      this.decodingTable[b] = -1; 
    for (b = 0; b < this.encodingTable.length; b++)
      this.decodingTable[this.encodingTable[b]] = (byte)b; 
  }
  
  public Base32Encoder() {
    this.encodingTable = DEAULT_ENCODING_TABLE;
    this.padding = 61;
    initialiseDecodingTable();
  }
  
  public Base32Encoder(byte[] paramArrayOfbyte, byte paramByte) {
    if (paramArrayOfbyte.length != 32)
      throw new IllegalArgumentException("encoding table needs to be length 32"); 
    this.encodingTable = Arrays.clone(paramArrayOfbyte);
    this.padding = paramByte;
    initialiseDecodingTable();
  }
  
  public int encode(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws IOException {
    int i = paramInt1;
    int j = paramInt1 + paramInt2 - 4;
    int k;
    for (k = paramInt3; i < j; k += 8) {
      encodeBlock(paramArrayOfbyte1, i, paramArrayOfbyte2, k);
      i += 5;
    } 
    int m = paramInt2 - i - paramInt1;
    if (m > 0) {
      byte[] arrayOfByte = new byte[5];
      System.arraycopy(paramArrayOfbyte1, i, arrayOfByte, 0, m);
      encodeBlock(arrayOfByte, 0, paramArrayOfbyte2, k);
      switch (m) {
        case 1:
          paramArrayOfbyte2[k + 2] = this.padding;
          paramArrayOfbyte2[k + 3] = this.padding;
          paramArrayOfbyte2[k + 4] = this.padding;
          paramArrayOfbyte2[k + 5] = this.padding;
          paramArrayOfbyte2[k + 6] = this.padding;
          paramArrayOfbyte2[k + 7] = this.padding;
          break;
        case 2:
          paramArrayOfbyte2[k + 4] = this.padding;
          paramArrayOfbyte2[k + 5] = this.padding;
          paramArrayOfbyte2[k + 6] = this.padding;
          paramArrayOfbyte2[k + 7] = this.padding;
          break;
        case 3:
          paramArrayOfbyte2[k + 5] = this.padding;
          paramArrayOfbyte2[k + 6] = this.padding;
          paramArrayOfbyte2[k + 7] = this.padding;
          break;
        case 4:
          paramArrayOfbyte2[k + 7] = this.padding;
          break;
      } 
      k += 8;
    } 
    return k - paramInt3;
  }
  
  private void encodeBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    byte b = paramArrayOfbyte1[paramInt1++];
    int i = paramArrayOfbyte1[paramInt1++] & 0xFF;
    int j = paramArrayOfbyte1[paramInt1++] & 0xFF;
    int k = paramArrayOfbyte1[paramInt1++] & 0xFF;
    int m = paramArrayOfbyte1[paramInt1] & 0xFF;
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[b >>> 3 & 0x1F];
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[(b << 2 | i >>> 6) & 0x1F];
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[i >>> 1 & 0x1F];
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[(i << 4 | j >>> 4) & 0x1F];
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[(j << 1 | k >>> 7) & 0x1F];
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[k >>> 2 & 0x1F];
    paramArrayOfbyte2[paramInt2++] = this.encodingTable[(k << 3 | m >>> 5) & 0x1F];
    paramArrayOfbyte2[paramInt2] = this.encodingTable[m & 0x1F];
  }
  
  public int getEncodedLength(int paramInt) {
    return (paramInt + 4) / 5 * 8;
  }
  
  public int getMaxDecodedLength(int paramInt) {
    return paramInt / 8 * 5;
  }
  
  public int encode(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, OutputStream paramOutputStream) throws IOException {
    if (paramInt2 < 0)
      return 0; 
    byte[] arrayOfByte = new byte[72];
    int i;
    for (i = paramInt2; i > 0; i -= j) {
      int j = Math.min(45, i);
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
    byte[] arrayOfByte = new byte[55];
    byte b = 0;
    int i = 0;
    int j;
    for (j = paramInt1 + paramInt2; j > paramInt1 && ignore((char)paramArrayOfbyte[j - 1]); j--);
    if (j == 0)
      return 0; 
    int k = 0;
    int m;
    for (m = j; m > paramInt1 && k != 8; m--) {
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
      k = nextI(paramArrayOfbyte, k, m);
      byte b5 = this.decodingTable[paramArrayOfbyte[k++]];
      k = nextI(paramArrayOfbyte, k, m);
      byte b6 = this.decodingTable[paramArrayOfbyte[k++]];
      k = nextI(paramArrayOfbyte, k, m);
      byte b7 = this.decodingTable[paramArrayOfbyte[k++]];
      k = nextI(paramArrayOfbyte, k, m);
      byte b8 = this.decodingTable[paramArrayOfbyte[k++]];
      if ((b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8) < 0)
        throw new IOException("invalid characters encountered in base32 data"); 
      arrayOfByte[b++] = (byte)(b1 << 3 | b2 >> 2);
      arrayOfByte[b++] = (byte)(b2 << 6 | b3 << 1 | b4 >> 4);
      arrayOfByte[b++] = (byte)(b4 << 4 | b5 >> 1);
      arrayOfByte[b++] = (byte)(b5 << 7 | b6 << 2 | b7 >> 3);
      arrayOfByte[b++] = (byte)(b7 << 5 | b8);
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
    int i4 = nextI(paramArrayOfbyte, i3 + 1, j);
    int i5 = nextI(paramArrayOfbyte, i4 + 1, j);
    int i6 = nextI(paramArrayOfbyte, i5 + 1, j);
    int i7 = nextI(paramArrayOfbyte, i6 + 1, j);
    i += decodeLastBlock(paramOutputStream, (char)paramArrayOfbyte[n], (char)paramArrayOfbyte[i1], (char)paramArrayOfbyte[i2], (char)paramArrayOfbyte[i3], (char)paramArrayOfbyte[i4], (char)paramArrayOfbyte[i5], (char)paramArrayOfbyte[i6], (char)paramArrayOfbyte[i7]);
    return i;
  }
  
  private int nextI(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    while (paramInt1 < paramInt2 && ignore((char)paramArrayOfbyte[paramInt1]))
      paramInt1++; 
    return paramInt1;
  }
  
  public int decode(String paramString, OutputStream paramOutputStream) throws IOException {
    byte[] arrayOfByte = Strings.toByteArray(paramString);
    return decode(arrayOfByte, 0, arrayOfByte.length, paramOutputStream);
  }
  
  private int decodeLastBlock(OutputStream paramOutputStream, char paramChar1, char paramChar2, char paramChar3, char paramChar4, char paramChar5, char paramChar6, char paramChar7, char paramChar8) throws IOException {
    if (paramChar8 == this.padding) {
      if (paramChar7 != this.padding) {
        byte b11 = this.decodingTable[paramChar1];
        byte b12 = this.decodingTable[paramChar2];
        byte b13 = this.decodingTable[paramChar3];
        byte b14 = this.decodingTable[paramChar4];
        byte b15 = this.decodingTable[paramChar5];
        byte b16 = this.decodingTable[paramChar6];
        byte b17 = this.decodingTable[paramChar7];
        if ((b11 | b12 | b13 | b14 | b15 | b16 | b17) < 0)
          throw new IOException("invalid characters encountered at end of base32 data"); 
        paramOutputStream.write(b11 << 3 | b12 >> 2);
        paramOutputStream.write(b12 << 6 | b13 << 1 | b14 >> 4);
        paramOutputStream.write(b14 << 4 | b15 >> 1);
        paramOutputStream.write(b15 << 7 | b16 << 2 | b17 >> 3);
        return 4;
      } 
      if (paramChar6 != this.padding)
        throw new IOException("invalid characters encountered at end of base32 data"); 
      if (paramChar5 != this.padding) {
        byte b11 = this.decodingTable[paramChar1];
        byte b12 = this.decodingTable[paramChar2];
        byte b13 = this.decodingTable[paramChar3];
        byte b14 = this.decodingTable[paramChar4];
        byte b15 = this.decodingTable[paramChar5];
        if ((b11 | b12 | b13 | b14 | b15) < 0)
          throw new IOException("invalid characters encountered at end of base32 data"); 
        paramOutputStream.write(b11 << 3 | b12 >> 2);
        paramOutputStream.write(b12 << 6 | b13 << 1 | b14 >> 4);
        paramOutputStream.write(b14 << 4 | b15 >> 1);
        return 3;
      } 
      if (paramChar4 != this.padding) {
        byte b11 = this.decodingTable[paramChar1];
        byte b12 = this.decodingTable[paramChar2];
        byte b13 = this.decodingTable[paramChar3];
        byte b14 = this.decodingTable[paramChar4];
        if ((b11 | b12 | b13 | b14) < 0)
          throw new IOException("invalid characters encountered at end of base32 data"); 
        paramOutputStream.write(b11 << 3 | b12 >> 2);
        paramOutputStream.write(b12 << 6 | b13 << 1 | b14 >> 4);
        return 2;
      } 
      if (paramChar3 != this.padding)
        throw new IOException("invalid characters encountered at end of base32 data"); 
      byte b9 = this.decodingTable[paramChar1];
      byte b10 = this.decodingTable[paramChar2];
      if ((b9 | b10) < 0)
        throw new IOException("invalid characters encountered at end of base32 data"); 
      paramOutputStream.write(b9 << 3 | b10 >> 2);
      return 1;
    } 
    byte b1 = this.decodingTable[paramChar1];
    byte b2 = this.decodingTable[paramChar2];
    byte b3 = this.decodingTable[paramChar3];
    byte b4 = this.decodingTable[paramChar4];
    byte b5 = this.decodingTable[paramChar5];
    byte b6 = this.decodingTable[paramChar6];
    byte b7 = this.decodingTable[paramChar7];
    byte b8 = this.decodingTable[paramChar8];
    if ((b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8) < 0)
      throw new IOException("invalid characters encountered at end of base32 data"); 
    paramOutputStream.write(b1 << 3 | b2 >> 2);
    paramOutputStream.write(b2 << 6 | b3 << 1 | b4 >> 4);
    paramOutputStream.write(b4 << 4 | b5 >> 1);
    paramOutputStream.write(b5 << 7 | b6 << 2 | b7 >> 3);
    paramOutputStream.write(b7 << 5 | b8);
    return 5;
  }
}
