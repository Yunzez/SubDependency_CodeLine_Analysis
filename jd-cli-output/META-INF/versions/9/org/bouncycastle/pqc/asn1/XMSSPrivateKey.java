package META-INF.versions.9.org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.util.Arrays;

public class XMSSPrivateKey extends ASN1Object {
  private final int version;
  
  private final int index;
  
  private final byte[] secretKeySeed;
  
  private final byte[] secretKeyPRF;
  
  private final byte[] publicSeed;
  
  private final byte[] root;
  
  private final int maxIndex;
  
  private final byte[] bdsState;
  
  public XMSSPrivateKey(int paramInt, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, byte[] paramArrayOfbyte5) {
    this.version = 0;
    this.index = paramInt;
    this.secretKeySeed = Arrays.clone(paramArrayOfbyte1);
    this.secretKeyPRF = Arrays.clone(paramArrayOfbyte2);
    this.publicSeed = Arrays.clone(paramArrayOfbyte3);
    this.root = Arrays.clone(paramArrayOfbyte4);
    this.bdsState = Arrays.clone(paramArrayOfbyte5);
    this.maxIndex = -1;
  }
  
  public XMSSPrivateKey(int paramInt1, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, byte[] paramArrayOfbyte5, int paramInt2) {
    this.version = 1;
    this.index = paramInt1;
    this.secretKeySeed = Arrays.clone(paramArrayOfbyte1);
    this.secretKeyPRF = Arrays.clone(paramArrayOfbyte2);
    this.publicSeed = Arrays.clone(paramArrayOfbyte3);
    this.root = Arrays.clone(paramArrayOfbyte4);
    this.bdsState = Arrays.clone(paramArrayOfbyte5);
    this.maxIndex = paramInt2;
  }
  
  private XMSSPrivateKey(ASN1Sequence paramASN1Sequence) {
    ASN1Integer aSN1Integer = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(0));
    if (!aSN1Integer.hasValue(0) && !aSN1Integer.hasValue(1))
      throw new IllegalArgumentException("unknown version of sequence"); 
    this.version = aSN1Integer.intValueExact();
    if (paramASN1Sequence.size() != 2 && paramASN1Sequence.size() != 3)
      throw new IllegalArgumentException("key sequence wrong size"); 
    ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(paramASN1Sequence.getObjectAt(1));
    this.index = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(0)).intValueExact();
    this.secretKeySeed = Arrays.clone(DEROctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets());
    this.secretKeyPRF = Arrays.clone(DEROctetString.getInstance(aSN1Sequence.getObjectAt(2)).getOctets());
    this.publicSeed = Arrays.clone(DEROctetString.getInstance(aSN1Sequence.getObjectAt(3)).getOctets());
    this.root = Arrays.clone(DEROctetString.getInstance(aSN1Sequence.getObjectAt(4)).getOctets());
    if (aSN1Sequence.size() == 6) {
      ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(aSN1Sequence.getObjectAt(5));
      if (aSN1TaggedObject.getTagNo() != 0)
        throw new IllegalArgumentException("unknown tag in XMSSPrivateKey"); 
      this.maxIndex = ASN1Integer.getInstance(aSN1TaggedObject, false).intValueExact();
    } else if (aSN1Sequence.size() == 5) {
      this.maxIndex = -1;
    } else {
      throw new IllegalArgumentException("keySeq should be 5 or 6 in length");
    } 
    if (paramASN1Sequence.size() == 3) {
      this.bdsState = Arrays.clone(DEROctetString.getInstance(ASN1TaggedObject.getInstance(paramASN1Sequence.getObjectAt(2)), true).getOctets());
    } else {
      this.bdsState = null;
    } 
  }
  
  public static org.bouncycastle.pqc.asn1.XMSSPrivateKey getInstance(Object paramObject) {
    if (paramObject instanceof org.bouncycastle.pqc.asn1.XMSSPrivateKey)
      return (org.bouncycastle.pqc.asn1.XMSSPrivateKey)paramObject; 
    if (paramObject != null)
      return new org.bouncycastle.pqc.asn1.XMSSPrivateKey(ASN1Sequence.getInstance(paramObject)); 
    return null;
  }
  
  public int getVersion() {
    return this.version;
  }
  
  public int getIndex() {
    return this.index;
  }
  
  public int getMaxIndex() {
    return this.maxIndex;
  }
  
  public byte[] getSecretKeySeed() {
    return Arrays.clone(this.secretKeySeed);
  }
  
  public byte[] getSecretKeyPRF() {
    return Arrays.clone(this.secretKeyPRF);
  }
  
  public byte[] getPublicSeed() {
    return Arrays.clone(this.publicSeed);
  }
  
  public byte[] getRoot() {
    return Arrays.clone(this.root);
  }
  
  public byte[] getBdsState() {
    return Arrays.clone(this.bdsState);
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
    if (this.maxIndex >= 0) {
      aSN1EncodableVector1.add(new ASN1Integer(1L));
    } else {
      aSN1EncodableVector1.add(new ASN1Integer(0L));
    } 
    ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
    aSN1EncodableVector2.add(new ASN1Integer(this.index));
    aSN1EncodableVector2.add(new DEROctetString(this.secretKeySeed));
    aSN1EncodableVector2.add(new DEROctetString(this.secretKeyPRF));
    aSN1EncodableVector2.add(new DEROctetString(this.publicSeed));
    aSN1EncodableVector2.add(new DEROctetString(this.root));
    if (this.maxIndex >= 0)
      aSN1EncodableVector2.add(new DERTaggedObject(false, 0, new ASN1Integer(this.maxIndex))); 
    aSN1EncodableVector1.add(new DERSequence(aSN1EncodableVector2));
    aSN1EncodableVector1.add(new DERTaggedObject(true, 0, new DEROctetString(this.bdsState)));
    return new DERSequence(aSN1EncodableVector1);
  }
}
