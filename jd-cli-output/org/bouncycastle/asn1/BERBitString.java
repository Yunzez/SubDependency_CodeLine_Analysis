package org.bouncycastle.asn1;

import java.io.IOException;

public class BERBitString extends ASN1BitString {
  private static final int DEFAULT_SEGMENT_LIMIT = 1000;
  
  private final int segmentLimit = 1000;
  
  private final ASN1BitString[] elements = null;
  
  static byte[] flattenBitStrings(ASN1BitString[] paramArrayOfASN1BitString) {
    int i = paramArrayOfASN1BitString.length;
    switch (i) {
      case 0:
        return new byte[] { 0 };
      case 1:
        return (paramArrayOfASN1BitString[0]).contents;
    } 
    int j = i - 1;
    int k = 0;
    for (byte b1 = 0; b1 < j; b1++) {
      byte[] arrayOfByte = (paramArrayOfASN1BitString[b1]).contents;
      if (arrayOfByte[0] != 0)
        throw new IllegalArgumentException("only the last nested bitstring can have padding"); 
      k += arrayOfByte.length - 1;
    } 
    byte[] arrayOfByte1 = (paramArrayOfASN1BitString[j]).contents;
    byte b = arrayOfByte1[0];
    k += arrayOfByte1.length;
    byte[] arrayOfByte2 = new byte[k];
    arrayOfByte2[0] = b;
    int m = 1;
    for (byte b2 = 0; b2 < i; b2++) {
      byte[] arrayOfByte = (paramArrayOfASN1BitString[b2]).contents;
      int n = arrayOfByte.length - 1;
      System.arraycopy(arrayOfByte, 1, arrayOfByte2, m, n);
      m += n;
    } 
    return arrayOfByte2;
  }
  
  public BERBitString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, 0);
  }
  
  public BERBitString(byte paramByte, int paramInt) {
    super(paramByte, paramInt);
  }
  
  public BERBitString(byte[] paramArrayOfbyte, int paramInt) {
    this(paramArrayOfbyte, paramInt, 1000);
  }
  
  public BERBitString(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    super(paramArrayOfbyte, paramInt1);
  }
  
  public BERBitString(ASN1Encodable paramASN1Encodable) throws IOException {
    this(paramASN1Encodable.toASN1Primitive().getEncoded("DER"), 0);
  }
  
  public BERBitString(ASN1BitString[] paramArrayOfASN1BitString) {
    this(paramArrayOfASN1BitString, 1000);
  }
  
  public BERBitString(ASN1BitString[] paramArrayOfASN1BitString, int paramInt) {
    super(flattenBitStrings(paramArrayOfASN1BitString), false);
  }
  
  BERBitString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
  
  boolean encodeConstructed() {
    return (null != this.elements || this.contents.length > this.segmentLimit);
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    if (!encodeConstructed())
      return DLBitString.encodedLength(paramBoolean, this.contents.length); 
    int i = paramBoolean ? 4 : 3;
    if (null != this.elements) {
      for (byte b = 0; b < this.elements.length; b++)
        i += this.elements[b].encodedLength(true); 
    } else if (this.contents.length >= 2) {
      int j = (this.contents.length - 2) / (this.segmentLimit - 1);
      i += j * DLBitString.encodedLength(true, this.segmentLimit);
      int k = this.contents.length - j * (this.segmentLimit - 1);
      i += DLBitString.encodedLength(true, k);
    } 
    return i;
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    if (!encodeConstructed()) {
      DLBitString.encode(paramASN1OutputStream, paramBoolean, this.contents, 0, this.contents.length);
      return;
    } 
    paramASN1OutputStream.writeIdentifier(paramBoolean, 35);
    paramASN1OutputStream.write(128);
    if (null != this.elements) {
      paramASN1OutputStream.writePrimitives((ASN1Primitive[])this.elements);
    } else if (this.contents.length >= 2) {
      byte b = this.contents[0];
      int i = this.contents.length;
      int j = i - 1;
      int k = this.segmentLimit - 1;
      while (j > k) {
        DLBitString.encode(paramASN1OutputStream, true, (byte)0, this.contents, i - j, k);
        j -= k;
      } 
      DLBitString.encode(paramASN1OutputStream, true, b, this.contents, i - j, j);
    } 
    paramASN1OutputStream.write(0);
    paramASN1OutputStream.write(0);
  }
}
