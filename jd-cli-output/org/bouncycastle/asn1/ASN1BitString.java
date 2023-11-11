package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.Arrays;

public abstract class ASN1BitString extends ASN1Primitive implements ASN1String, ASN1BitStringParser {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BitString.class, 3) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1BitString.createPrimitive(param1DEROctetString.getOctets());
      }
      
      ASN1Primitive fromImplicitConstructed(ASN1Sequence param1ASN1Sequence) {
        return param1ASN1Sequence.toASN1BitString();
      }
    };
  
  private static final char[] table = new char[] { 
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
      'A', 'B', 'C', 'D', 'E', 'F' };
  
  final byte[] contents;
  
  public static ASN1BitString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1BitString)
      return (ASN1BitString)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1BitString)
        return (ASN1BitString)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (ASN1BitString)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct BIT STRING from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1BitString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1BitString)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  protected static int getPadBits(int paramInt) {
    int i = 0;
    byte b;
    for (b = 3; b >= 0; b--) {
      if (b != 0) {
        if (paramInt >> b * 8 != 0) {
          i = paramInt >> b * 8 & 0xFF;
          break;
        } 
      } else if (paramInt != 0) {
        i = paramInt & 0xFF;
        break;
      } 
    } 
    if (i == 0)
      return 0; 
    for (b = 1; ((i <<= 1) & 0xFF) != 0; b++);
    return 8 - b;
  }
  
  protected static byte[] getBytes(int paramInt) {
    if (paramInt == 0)
      return new byte[0]; 
    byte b1 = 4;
    for (byte b2 = 3; b2 >= 1 && (paramInt & 255 << b2 * 8) == 0; b2--)
      b1--; 
    byte[] arrayOfByte = new byte[b1];
    for (byte b3 = 0; b3 < b1; b3++)
      arrayOfByte[b3] = (byte)(paramInt >> b3 * 8 & 0xFF); 
    return arrayOfByte;
  }
  
  ASN1BitString(byte paramByte, int paramInt) {
    if (paramInt > 7 || paramInt < 0)
      throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0"); 
    this.contents = new byte[] { (byte)paramInt, paramByte };
  }
  
  ASN1BitString(byte[] paramArrayOfbyte, int paramInt) {
    if (paramArrayOfbyte == null)
      throw new NullPointerException("'data' cannot be null"); 
    if (paramArrayOfbyte.length == 0 && paramInt != 0)
      throw new IllegalArgumentException("zero length data with non-zero pad bits"); 
    if (paramInt > 7 || paramInt < 0)
      throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0"); 
    this.contents = Arrays.prepend(paramArrayOfbyte, (byte)paramInt);
  }
  
  ASN1BitString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    if (paramBoolean) {
      if (null == paramArrayOfbyte)
        throw new NullPointerException("'contents' cannot be null"); 
      if (paramArrayOfbyte.length < 1)
        throw new IllegalArgumentException("'contents' cannot be empty"); 
      int i = paramArrayOfbyte[0] & 0xFF;
      if (i > 0) {
        if (paramArrayOfbyte.length < 2)
          throw new IllegalArgumentException("zero length data with non-zero pad bits"); 
        if (i > 7)
          throw new IllegalArgumentException("pad bits cannot be greater than 7 or less than 0"); 
      } 
    } 
    this.contents = paramArrayOfbyte;
  }
  
  public InputStream getBitStream() throws IOException {
    return new ByteArrayInputStream(this.contents, 1, this.contents.length - 1);
  }
  
  public InputStream getOctetStream() throws IOException {
    int i = this.contents[0] & 0xFF;
    if (0 != i)
      throw new IOException("expected octet-aligned bitstring, but found padBits: " + i); 
    return getBitStream();
  }
  
  public ASN1BitStringParser parser() {
    return this;
  }
  
  public String getString() {
    byte[] arrayOfByte;
    try {
      arrayOfByte = getEncoded();
    } catch (IOException iOException) {
      throw new ASN1ParsingException("Internal error encoding BitString: " + iOException.getMessage(), iOException);
    } 
    StringBuffer stringBuffer = new StringBuffer(1 + arrayOfByte.length * 2);
    stringBuffer.append('#');
    for (byte b = 0; b != arrayOfByte.length; b++) {
      byte b1 = arrayOfByte[b];
      stringBuffer.append(table[b1 >>> 4 & 0xF]);
      stringBuffer.append(table[b1 & 0xF]);
    } 
    return stringBuffer.toString();
  }
  
  public int intValue() {
    int i = 0;
    int j = Math.min(5, this.contents.length - 1);
    int k;
    for (k = 1; k < j; k++)
      i |= (this.contents[k] & 0xFF) << 8 * (k - 1); 
    if (1 <= j && j < 5) {
      k = this.contents[0] & 0xFF;
      byte b = (byte)(this.contents[j] & 255 << k);
      i |= (b & 0xFF) << 8 * (j - 1);
    } 
    return i;
  }
  
  public byte[] getOctets() {
    if (this.contents[0] != 0)
      throw new IllegalStateException("attempt to get non-octet aligned data from BIT STRING"); 
    return Arrays.copyOfRange(this.contents, 1, this.contents.length);
  }
  
  public byte[] getBytes() {
    if (this.contents.length == 1)
      return ASN1OctetString.EMPTY_OCTETS; 
    int i = this.contents[0] & 0xFF;
    byte[] arrayOfByte = Arrays.copyOfRange(this.contents, 1, this.contents.length);
    arrayOfByte[arrayOfByte.length - 1] = (byte)(arrayOfByte[arrayOfByte.length - 1] & (byte)(255 << i));
    return arrayOfByte;
  }
  
  public int getPadBits() {
    return this.contents[0] & 0xFF;
  }
  
  public String toString() {
    return getString();
  }
  
  public int hashCode() {
    if (this.contents.length < 2)
      return 1; 
    int i = this.contents[0] & 0xFF;
    int j = this.contents.length - 1;
    byte b = (byte)(this.contents[j] & 255 << i);
    int k = Arrays.hashCode(this.contents, 0, j);
    k *= 257;
    k ^= b;
    return k;
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1BitString))
      return false; 
    ASN1BitString aSN1BitString = (ASN1BitString)paramASN1Primitive;
    byte[] arrayOfByte1 = this.contents;
    byte[] arrayOfByte2 = aSN1BitString.contents;
    int i = arrayOfByte1.length;
    if (arrayOfByte2.length != i)
      return false; 
    if (i == 1)
      return true; 
    int j = i - 1;
    int k;
    for (k = 0; k < j; k++) {
      if (arrayOfByte1[k] != arrayOfByte2[k])
        return false; 
    } 
    k = arrayOfByte1[0] & 0xFF;
    byte b1 = (byte)(arrayOfByte1[j] & 255 << k);
    byte b2 = (byte)(arrayOfByte2[j] & 255 << k);
    return (b1 == b2);
  }
  
  public ASN1Primitive getLoadedObject() {
    return toASN1Primitive();
  }
  
  ASN1Primitive toDERObject() {
    return new DERBitString(this.contents, false);
  }
  
  ASN1Primitive toDLObject() {
    return new DLBitString(this.contents, false);
  }
  
  static ASN1BitString createPrimitive(byte[] paramArrayOfbyte) {
    int i = paramArrayOfbyte.length;
    if (i < 1)
      throw new IllegalArgumentException("truncated BIT STRING detected"); 
    int j = paramArrayOfbyte[0] & 0xFF;
    if (j > 0) {
      if (j > 7 || i < 2)
        throw new IllegalArgumentException("invalid pad bits detected"); 
      byte b = paramArrayOfbyte[i - 1];
      if (b != (byte)(b & 255 << j))
        return new DLBitString(paramArrayOfbyte, false); 
    } 
    return new DERBitString(paramArrayOfbyte, false);
  }
}
