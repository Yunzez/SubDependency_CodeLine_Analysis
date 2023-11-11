package org.bouncycastle.asn1.pkcs;

import java.io.IOException;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.BigIntegers;

public class PrivateKeyInfo extends ASN1Object {
  private ASN1Integer version;
  
  private AlgorithmIdentifier privateKeyAlgorithm;
  
  private ASN1OctetString privateKey;
  
  private ASN1Set attributes;
  
  private ASN1BitString publicKey;
  
  public static PrivateKeyInfo getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static PrivateKeyInfo getInstance(Object paramObject) {
    return (paramObject instanceof PrivateKeyInfo) ? (PrivateKeyInfo)paramObject : ((paramObject != null) ? new PrivateKeyInfo(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  private static int getVersionValue(ASN1Integer paramASN1Integer) {
    int i = paramASN1Integer.intValueExact();
    if (i < 0 || i > 1)
      throw new IllegalArgumentException("invalid version for private key info"); 
    return i;
  }
  
  public PrivateKeyInfo(AlgorithmIdentifier paramAlgorithmIdentifier, ASN1Encodable paramASN1Encodable) throws IOException {
    this(paramAlgorithmIdentifier, paramASN1Encodable, null, null);
  }
  
  public PrivateKeyInfo(AlgorithmIdentifier paramAlgorithmIdentifier, ASN1Encodable paramASN1Encodable, ASN1Set paramASN1Set) throws IOException {
    this(paramAlgorithmIdentifier, paramASN1Encodable, paramASN1Set, null);
  }
  
  public PrivateKeyInfo(AlgorithmIdentifier paramAlgorithmIdentifier, ASN1Encodable paramASN1Encodable, ASN1Set paramASN1Set, byte[] paramArrayOfbyte) throws IOException {
    this.version = new ASN1Integer((paramArrayOfbyte != null) ? BigIntegers.ONE : BigIntegers.ZERO);
    this.privateKeyAlgorithm = paramAlgorithmIdentifier;
    this.privateKey = new DEROctetString(paramASN1Encodable);
    this.attributes = paramASN1Set;
    this.publicKey = (paramArrayOfbyte == null) ? null : new DERBitString(paramArrayOfbyte);
  }
  
  private PrivateKeyInfo(ASN1Sequence paramASN1Sequence) {
    Enumeration<ASN1TaggedObject> enumeration = paramASN1Sequence.getObjects();
    this.version = ASN1Integer.getInstance(enumeration.nextElement());
    int i = getVersionValue(this.version);
    this.privateKeyAlgorithm = AlgorithmIdentifier.getInstance(enumeration.nextElement());
    this.privateKey = ASN1OctetString.getInstance(enumeration.nextElement());
    int j = -1;
    while (enumeration.hasMoreElements()) {
      ASN1TaggedObject aSN1TaggedObject = enumeration.nextElement();
      int k = aSN1TaggedObject.getTagNo();
      if (k <= j)
        throw new IllegalArgumentException("invalid optional field in private key info"); 
      j = k;
      switch (k) {
        case 0:
          this.attributes = ASN1Set.getInstance(aSN1TaggedObject, false);
          continue;
        case 1:
          if (i < 1)
            throw new IllegalArgumentException("'publicKey' requires version v2(1) or later"); 
          this.publicKey = DERBitString.getInstance(aSN1TaggedObject, false);
          continue;
      } 
      throw new IllegalArgumentException("unknown optional field in private key info");
    } 
  }
  
  public ASN1Integer getVersion() {
    return this.version;
  }
  
  public ASN1Set getAttributes() {
    return this.attributes;
  }
  
  public AlgorithmIdentifier getPrivateKeyAlgorithm() {
    return this.privateKeyAlgorithm;
  }
  
  public ASN1OctetString getPrivateKey() {
    return new DEROctetString(this.privateKey.getOctets());
  }
  
  public ASN1Encodable parsePrivateKey() throws IOException {
    return ASN1Primitive.fromByteArray(this.privateKey.getOctets());
  }
  
  public boolean hasPublicKey() {
    return (this.publicKey != null);
  }
  
  public ASN1Encodable parsePublicKey() throws IOException {
    return (this.publicKey == null) ? null : ASN1Primitive.fromByteArray(this.publicKey.getOctets());
  }
  
  public ASN1BitString getPublicKeyData() {
    return this.publicKey;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(5);
    aSN1EncodableVector.add(this.version);
    aSN1EncodableVector.add(this.privateKeyAlgorithm);
    aSN1EncodableVector.add(this.privateKey);
    if (this.attributes != null)
      aSN1EncodableVector.add(new DERTaggedObject(false, 0, this.attributes)); 
    if (this.publicKey != null)
      aSN1EncodableVector.add(new DERTaggedObject(false, 1, this.publicKey)); 
    return new DERSequence(aSN1EncodableVector);
  }
}
