package org.bouncycastle.asn1.x509;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.BigIntegers;

public class CRLNumber extends ASN1Object {
  private BigInteger number;
  
  public CRLNumber(BigInteger paramBigInteger) {
    if (BigIntegers.ZERO.compareTo(paramBigInteger) > 0)
      throw new IllegalArgumentException("Invalid CRL number : not in (0..MAX)"); 
    this.number = paramBigInteger;
  }
  
  public BigInteger getCRLNumber() {
    return this.number;
  }
  
  public String toString() {
    return "CRLNumber: " + getCRLNumber();
  }
  
  public ASN1Primitive toASN1Primitive() {
    return new ASN1Integer(this.number);
  }
  
  public static CRLNumber getInstance(Object paramObject) {
    return (paramObject instanceof CRLNumber) ? (CRLNumber)paramObject : ((paramObject != null) ? new CRLNumber(ASN1Integer.getInstance(paramObject).getValue()) : null);
  }
}
