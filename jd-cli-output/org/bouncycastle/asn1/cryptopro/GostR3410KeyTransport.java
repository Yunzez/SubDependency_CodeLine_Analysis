package org.bouncycastle.asn1.cryptopro;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class GostR3410KeyTransport extends ASN1Object {
  private final Gost2814789EncryptedKey sessionEncryptedKey;
  
  private final GostR3410TransportParameters transportParameters;
  
  private GostR3410KeyTransport(ASN1Sequence paramASN1Sequence) {
    this.sessionEncryptedKey = Gost2814789EncryptedKey.getInstance(paramASN1Sequence.getObjectAt(0));
    this.transportParameters = GostR3410TransportParameters.getInstance(ASN1TaggedObject.getInstance(paramASN1Sequence.getObjectAt(1)), false);
  }
  
  public GostR3410KeyTransport(Gost2814789EncryptedKey paramGost2814789EncryptedKey, GostR3410TransportParameters paramGostR3410TransportParameters) {
    this.sessionEncryptedKey = paramGost2814789EncryptedKey;
    this.transportParameters = paramGostR3410TransportParameters;
  }
  
  public static GostR3410KeyTransport getInstance(Object paramObject) {
    return (paramObject instanceof GostR3410KeyTransport) ? (GostR3410KeyTransport)paramObject : ((paramObject != null) ? new GostR3410KeyTransport(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public Gost2814789EncryptedKey getSessionEncryptedKey() {
    return this.sessionEncryptedKey;
  }
  
  public GostR3410TransportParameters getTransportParameters() {
    return this.transportParameters;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    aSN1EncodableVector.add(this.sessionEncryptedKey);
    if (this.transportParameters != null)
      aSN1EncodableVector.add(new DERTaggedObject(false, 0, this.transportParameters)); 
    return new DERSequence(aSN1EncodableVector);
  }
}
