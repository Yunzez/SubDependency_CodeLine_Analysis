package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.util.Arrays;

public abstract class ASN1BMPString extends ASN1Primitive implements ASN1String {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1BMPString.class, 30) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1BMPString.createPrimitive(param1DEROctetString.getOctets());
      }
    };
  
  final char[] string;
  
  public static ASN1BMPString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1BMPString)
      return (ASN1BMPString)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1BMPString)
        return (ASN1BMPString)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (ASN1BMPString)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1BMPString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1BMPString)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  ASN1BMPString(String paramString) {
    if (paramString == null)
      throw new NullPointerException("'string' cannot be null"); 
    this.string = paramString.toCharArray();
  }
  
  ASN1BMPString(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      throw new NullPointerException("'string' cannot be null"); 
    int i = paramArrayOfbyte.length;
    if (0 != (i & 0x1))
      throw new IllegalArgumentException("malformed BMPString encoding encountered"); 
    int j = i / 2;
    char[] arrayOfChar = new char[j];
    for (int k = 0; k != j; k++)
      arrayOfChar[k] = (char)(paramArrayOfbyte[2 * k] << 8 | paramArrayOfbyte[2 * k + 1] & 0xFF); 
    this.string = arrayOfChar;
  }
  
  ASN1BMPString(char[] paramArrayOfchar) {
    if (paramArrayOfchar == null)
      throw new NullPointerException("'string' cannot be null"); 
    this.string = paramArrayOfchar;
  }
  
  public final String getString() {
    return new String(this.string);
  }
  
  public String toString() {
    return getString();
  }
  
  final boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1BMPString))
      return false; 
    ASN1BMPString aSN1BMPString = (ASN1BMPString)paramASN1Primitive;
    return Arrays.areEqual(this.string, aSN1BMPString.string);
  }
  
  public final int hashCode() {
    return Arrays.hashCode(this.string);
  }
  
  final boolean encodeConstructed() {
    return false;
  }
  
  final int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.string.length * 2);
  }
  
  final void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    int i = this.string.length;
    paramASN1OutputStream.writeIdentifier(paramBoolean, 30);
    paramASN1OutputStream.writeDL(i * 2);
    byte[] arrayOfByte = new byte[8];
    byte b = 0;
    int j = i & 0xFFFFFFFC;
    while (b < j) {
      char c1 = this.string[b];
      char c2 = this.string[b + 1];
      char c3 = this.string[b + 2];
      char c4 = this.string[b + 3];
      b += 4;
      arrayOfByte[0] = (byte)(c1 >> 8);
      arrayOfByte[1] = (byte)c1;
      arrayOfByte[2] = (byte)(c2 >> 8);
      arrayOfByte[3] = (byte)c2;
      arrayOfByte[4] = (byte)(c3 >> 8);
      arrayOfByte[5] = (byte)c3;
      arrayOfByte[6] = (byte)(c4 >> 8);
      arrayOfByte[7] = (byte)c4;
      paramASN1OutputStream.write(arrayOfByte, 0, 8);
    } 
    if (b < i) {
      byte b1 = 0;
      while (true) {
        char c = this.string[b];
        b++;
        arrayOfByte[b1++] = (byte)(c >> 8);
        arrayOfByte[b1++] = (byte)c;
        if (b >= i) {
          paramASN1OutputStream.write(arrayOfByte, 0, b1);
          break;
        } 
      } 
    } 
  }
  
  static ASN1BMPString createPrimitive(byte[] paramArrayOfbyte) {
    return new DERBMPString(paramArrayOfbyte);
  }
  
  static ASN1BMPString createPrimitive(char[] paramArrayOfchar) {
    return new DERBMPString(paramArrayOfchar);
  }
}
