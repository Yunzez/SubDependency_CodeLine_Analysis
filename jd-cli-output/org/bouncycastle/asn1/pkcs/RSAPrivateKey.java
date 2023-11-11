package org.bouncycastle.asn1.pkcs;

import java.math.BigInteger;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class RSAPrivateKey extends ASN1Object {
  private BigInteger version;
  
  private BigInteger modulus;
  
  private BigInteger publicExponent;
  
  private BigInteger privateExponent;
  
  private BigInteger prime1;
  
  private BigInteger prime2;
  
  private BigInteger exponent1;
  
  private BigInteger exponent2;
  
  private BigInteger coefficient;
  
  private ASN1Sequence otherPrimeInfos = null;
  
  public static RSAPrivateKey getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static RSAPrivateKey getInstance(Object paramObject) {
    return (paramObject instanceof RSAPrivateKey) ? (RSAPrivateKey)paramObject : ((paramObject != null) ? new RSAPrivateKey(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public RSAPrivateKey(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, BigInteger paramBigInteger4, BigInteger paramBigInteger5, BigInteger paramBigInteger6, BigInteger paramBigInteger7, BigInteger paramBigInteger8) {
    this.version = BigInteger.valueOf(0L);
    this.modulus = paramBigInteger1;
    this.publicExponent = paramBigInteger2;
    this.privateExponent = paramBigInteger3;
    this.prime1 = paramBigInteger4;
    this.prime2 = paramBigInteger5;
    this.exponent1 = paramBigInteger6;
    this.exponent2 = paramBigInteger7;
    this.coefficient = paramBigInteger8;
  }
  
  private RSAPrivateKey(ASN1Sequence paramASN1Sequence) {
    Enumeration<ASN1Integer> enumeration = paramASN1Sequence.getObjects();
    ASN1Integer aSN1Integer = enumeration.nextElement();
    int i = aSN1Integer.intValueExact();
    if (i < 0 || i > 1)
      throw new IllegalArgumentException("wrong version for RSA private key"); 
    this.version = aSN1Integer.getValue();
    this.modulus = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.publicExponent = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.privateExponent = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.prime1 = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.prime2 = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.exponent1 = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.exponent2 = ((ASN1Integer)enumeration.nextElement()).getValue();
    this.coefficient = ((ASN1Integer)enumeration.nextElement()).getValue();
    if (enumeration.hasMoreElements())
      this.otherPrimeInfos = (ASN1Sequence)enumeration.nextElement(); 
  }
  
  public BigInteger getVersion() {
    return this.version;
  }
  
  public BigInteger getModulus() {
    return this.modulus;
  }
  
  public BigInteger getPublicExponent() {
    return this.publicExponent;
  }
  
  public BigInteger getPrivateExponent() {
    return this.privateExponent;
  }
  
  public BigInteger getPrime1() {
    return this.prime1;
  }
  
  public BigInteger getPrime2() {
    return this.prime2;
  }
  
  public BigInteger getExponent1() {
    return this.exponent1;
  }
  
  public BigInteger getExponent2() {
    return this.exponent2;
  }
  
  public BigInteger getCoefficient() {
    return this.coefficient;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(10);
    aSN1EncodableVector.add(new ASN1Integer(this.version));
    aSN1EncodableVector.add(new ASN1Integer(getModulus()));
    aSN1EncodableVector.add(new ASN1Integer(getPublicExponent()));
    aSN1EncodableVector.add(new ASN1Integer(getPrivateExponent()));
    aSN1EncodableVector.add(new ASN1Integer(getPrime1()));
    aSN1EncodableVector.add(new ASN1Integer(getPrime2()));
    aSN1EncodableVector.add(new ASN1Integer(getExponent1()));
    aSN1EncodableVector.add(new ASN1Integer(getExponent2()));
    aSN1EncodableVector.add(new ASN1Integer(getCoefficient()));
    if (this.otherPrimeInfos != null)
      aSN1EncodableVector.add(this.otherPrimeInfos); 
    return new DERSequence(aSN1EncodableVector);
  }
}
