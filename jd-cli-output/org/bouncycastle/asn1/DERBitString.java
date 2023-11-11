package org.bouncycastle.asn1;

import java.io.IOException;

public class DERBitString extends ASN1BitString {
  public static DERBitString convert(ASN1BitString paramASN1BitString) {
    return (DERBitString)paramASN1BitString.toDERObject();
  }
  
  public static DERBitString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERBitString)
      return (DERBitString)paramObject; 
    if (paramObject instanceof ASN1BitString)
      return convert((ASN1BitString)paramObject); 
    if (paramObject instanceof byte[])
      try {
        return convert((ASN1BitString)fromByteArray((byte[])paramObject));
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERBitString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERBitString) ? getInstance(aSN1Primitive) : fromOctetString(ASN1OctetString.getInstance(aSN1Primitive));
  }
  
  public DERBitString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, 0);
  }
  
  public DERBitString(byte paramByte, int paramInt) {
    super(paramByte, paramInt);
  }
  
  public DERBitString(byte[] paramArrayOfbyte, int paramInt) {
    super(paramArrayOfbyte, paramInt);
  }
  
  public DERBitString(int paramInt) {
    super(getBytes(paramInt), getPadBits(paramInt));
  }
  
  public DERBitString(ASN1Encodable paramASN1Encodable) throws IOException {
    super(paramASN1Encodable.toASN1Primitive().getEncoded("DER"), 0);
  }
  
  DERBitString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
  
  boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    int i = this.contents[0] & 0xFF;
    int j = this.contents.length;
    int k = j - 1;
    byte b1 = this.contents[k];
    byte b2 = (byte)(this.contents[k] & 255 << i);
    if (b1 == b2) {
      paramASN1OutputStream.writeEncodingDL(paramBoolean, 3, this.contents);
    } else {
      paramASN1OutputStream.writeEncodingDL(paramBoolean, 3, this.contents, 0, k, b2);
    } 
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
  
  static DERBitString fromOctetString(ASN1OctetString paramASN1OctetString) {
    return new DERBitString(paramASN1OctetString.getOctets(), true);
  }
}
