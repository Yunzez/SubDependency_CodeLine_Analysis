package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECNamedDomainParameters extends ECDomainParameters {
  private ASN1ObjectIdentifier name;
  
  public ECNamedDomainParameters(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ECCurve paramECCurve, ECPoint paramECPoint, BigInteger paramBigInteger) {
    this(paramASN1ObjectIdentifier, paramECCurve, paramECPoint, paramBigInteger, ECConstants.ONE, null);
  }
  
  public ECNamedDomainParameters(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ECCurve paramECCurve, ECPoint paramECPoint, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    this(paramASN1ObjectIdentifier, paramECCurve, paramECPoint, paramBigInteger1, paramBigInteger2, null);
  }
  
  public ECNamedDomainParameters(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ECCurve paramECCurve, ECPoint paramECPoint, BigInteger paramBigInteger1, BigInteger paramBigInteger2, byte[] paramArrayOfbyte) {
    super(paramECCurve, paramECPoint, paramBigInteger1, paramBigInteger2, paramArrayOfbyte);
    this.name = paramASN1ObjectIdentifier;
  }
  
  public ECNamedDomainParameters(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ECDomainParameters paramECDomainParameters) {
    super(paramECDomainParameters.getCurve(), paramECDomainParameters.getG(), paramECDomainParameters.getN(), paramECDomainParameters.getH(), paramECDomainParameters.getSeed());
    this.name = paramASN1ObjectIdentifier;
  }
  
  public ECNamedDomainParameters(ASN1ObjectIdentifier paramASN1ObjectIdentifier, X9ECParameters paramX9ECParameters) {
    super(paramX9ECParameters);
    this.name = paramASN1ObjectIdentifier;
  }
  
  public ASN1ObjectIdentifier getName() {
    return this.name;
  }
}
