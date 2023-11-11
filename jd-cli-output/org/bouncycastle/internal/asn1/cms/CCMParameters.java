package org.bouncycastle.internal.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class CCMParameters extends ASN1Object {
  private byte[] nonce;
  
  private int icvLen;
  
  public static CCMParameters getInstance(Object paramObject) {
    return (paramObject instanceof CCMParameters) ? (CCMParameters)paramObject : ((paramObject != null) ? new CCMParameters(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  private CCMParameters(ASN1Sequence paramASN1Sequence) {
    this.nonce = ASN1OctetString.getInstance(paramASN1Sequence.getObjectAt(0)).getOctets();
    if (paramASN1Sequence.size() == 2) {
      this.icvLen = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(1)).intValueExact();
    } else {
      this.icvLen = 12;
    } 
  }
  
  public CCMParameters(byte[] paramArrayOfbyte, int paramInt) {
    this.nonce = Arrays.clone(paramArrayOfbyte);
    this.icvLen = paramInt;
  }
  
  public byte[] getNonce() {
    return Arrays.clone(this.nonce);
  }
  
  public int getIcvLen() {
    return this.icvLen;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    aSN1EncodableVector.add(new DEROctetString(this.nonce));
    if (this.icvLen != 12)
      aSN1EncodableVector.add(new ASN1Integer(this.icvLen)); 
    return new DERSequence(aSN1EncodableVector);
  }
}