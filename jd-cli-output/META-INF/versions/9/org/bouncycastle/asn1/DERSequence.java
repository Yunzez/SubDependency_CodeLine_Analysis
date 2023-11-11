package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BERBitString;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERExternal;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DLSet;

public class DERSequence extends ASN1Sequence {
  public static org.bouncycastle.asn1.DERSequence convert(ASN1Sequence paramASN1Sequence) {
    return (org.bouncycastle.asn1.DERSequence)paramASN1Sequence.toDERObject();
  }
  
  private int contentsLength = -1;
  
  public DERSequence() {}
  
  public DERSequence(ASN1Encodable paramASN1Encodable) {
    super(paramASN1Encodable);
  }
  
  public DERSequence(ASN1EncodableVector paramASN1EncodableVector) {
    super(paramASN1EncodableVector);
  }
  
  public DERSequence(ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramArrayOfASN1Encodable);
  }
  
  DERSequence(ASN1Encodable[] paramArrayOfASN1Encodable, boolean paramBoolean) {
    super(paramArrayOfASN1Encodable, paramBoolean);
  }
  
  private int getContentsLength() throws IOException {
    if (this.contentsLength < 0) {
      int i = this.elements.length;
      int j = 0;
      for (byte b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDERObject();
        j += aSN1Primitive.encodedLength(true);
      } 
      this.contentsLength = j;
    } 
    return this.contentsLength;
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, getContentsLength());
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeIdentifier(paramBoolean, 48);
    DEROutputStream dEROutputStream = paramASN1OutputStream.getDERSubStream();
    int i = this.elements.length;
    if (this.contentsLength >= 0 || i > 16) {
      paramASN1OutputStream.writeDL(getContentsLength());
      for (byte b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDERObject();
        aSN1Primitive.encode(dEROutputStream, true);
      } 
    } else {
      int j = 0;
      ASN1Primitive[] arrayOfASN1Primitive = new ASN1Primitive[i];
      byte b;
      for (b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDERObject();
        arrayOfASN1Primitive[b] = aSN1Primitive;
        j += aSN1Primitive.encodedLength(true);
      } 
      this.contentsLength = j;
      paramASN1OutputStream.writeDL(j);
      for (b = 0; b < i; b++)
        arrayOfASN1Primitive[b].encode(dEROutputStream, true); 
    } 
  }
  
  ASN1BitString toASN1BitString() {
    return new DERBitString(BERBitString.flattenBitStrings(getConstructedBitStrings()), false);
  }
  
  ASN1External toASN1External() {
    return new DERExternal(this);
  }
  
  ASN1OctetString toASN1OctetString() {
    return new DEROctetString(BEROctetString.flattenOctetStrings(getConstructedOctetStrings()));
  }
  
  ASN1Set toASN1Set() {
    return new DLSet(false, toArrayInternal());
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}
