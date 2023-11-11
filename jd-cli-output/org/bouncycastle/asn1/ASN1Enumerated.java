package org.bouncycastle.asn1;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.util.Arrays;

public class ASN1Enumerated extends ASN1Primitive {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Enumerated.class, 10) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1Enumerated.createPrimitive(param1DEROctetString.getOctets(), false);
      }
    };
  
  private final byte[] contents;
  
  private final int start;
  
  private static final ASN1Enumerated[] cache = new ASN1Enumerated[12];
  
  public static ASN1Enumerated getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1Enumerated)
      return (ASN1Enumerated)paramObject; 
    if (paramObject instanceof byte[])
      try {
        return (ASN1Enumerated)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1Enumerated getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1Enumerated)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public ASN1Enumerated(int paramInt) {
    if (paramInt < 0)
      throw new IllegalArgumentException("enumerated must be non-negative"); 
    this.contents = BigInteger.valueOf(paramInt).toByteArray();
    this.start = 0;
  }
  
  public ASN1Enumerated(BigInteger paramBigInteger) {
    if (paramBigInteger.signum() < 0)
      throw new IllegalArgumentException("enumerated must be non-negative"); 
    this.contents = paramBigInteger.toByteArray();
    this.start = 0;
  }
  
  public ASN1Enumerated(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  ASN1Enumerated(byte[] paramArrayOfbyte, boolean paramBoolean) {
    if (ASN1Integer.isMalformed(paramArrayOfbyte))
      throw new IllegalArgumentException("malformed enumerated"); 
    if (0 != (paramArrayOfbyte[0] & 0x80))
      throw new IllegalArgumentException("enumerated must be non-negative"); 
    this.contents = paramBoolean ? Arrays.clone(paramArrayOfbyte) : paramArrayOfbyte;
    this.start = ASN1Integer.signBytesToSkip(paramArrayOfbyte);
  }
  
  public BigInteger getValue() {
    return new BigInteger(this.contents);
  }
  
  public boolean hasValue(int paramInt) {
    return (this.contents.length - this.start <= 4 && ASN1Integer.intValue(this.contents, this.start, -1) == paramInt);
  }
  
  public boolean hasValue(BigInteger paramBigInteger) {
    return (null != paramBigInteger && ASN1Integer.intValue(this.contents, this.start, -1) == paramBigInteger.intValue() && getValue().equals(paramBigInteger));
  }
  
  public int intValueExact() {
    int i = this.contents.length - this.start;
    if (i > 4)
      throw new ArithmeticException("ASN.1 Enumerated out of int range"); 
    return ASN1Integer.intValue(this.contents, this.start, -1);
  }
  
  boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 10, this.contents);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1Enumerated))
      return false; 
    ASN1Enumerated aSN1Enumerated = (ASN1Enumerated)paramASN1Primitive;
    return Arrays.areEqual(this.contents, aSN1Enumerated.contents);
  }
  
  public int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  static ASN1Enumerated createPrimitive(byte[] paramArrayOfbyte, boolean paramBoolean) {
    if (paramArrayOfbyte.length > 1)
      return new ASN1Enumerated(paramArrayOfbyte, paramBoolean); 
    if (paramArrayOfbyte.length == 0)
      throw new IllegalArgumentException("ENUMERATED has zero length"); 
    int i = paramArrayOfbyte[0] & 0xFF;
    if (i >= cache.length)
      return new ASN1Enumerated(paramArrayOfbyte, paramBoolean); 
    ASN1Enumerated aSN1Enumerated = cache[i];
    if (aSN1Enumerated == null)
      aSN1Enumerated = cache[i] = new ASN1Enumerated(paramArrayOfbyte, paramBoolean); 
    return aSN1Enumerated;
  }
}
