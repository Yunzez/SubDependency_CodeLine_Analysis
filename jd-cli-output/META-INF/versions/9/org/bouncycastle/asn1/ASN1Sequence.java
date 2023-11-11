package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;

public abstract class ASN1Sequence extends ASN1Primitive implements Iterable<ASN1Encodable> {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1Sequence.class, 16);
  
  ASN1Encodable[] elements;
  
  public static org.bouncycastle.asn1.ASN1Sequence getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1Sequence)
      return (org.bouncycastle.asn1.ASN1Sequence)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1Sequence)
        return (org.bouncycastle.asn1.ASN1Sequence)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (org.bouncycastle.asn1.ASN1Sequence)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct sequence from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("unknown object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1Sequence getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1Sequence)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  protected ASN1Sequence() {
    this.elements = ASN1EncodableVector.EMPTY_ELEMENTS;
  }
  
  protected ASN1Sequence(ASN1Encodable paramASN1Encodable) {
    if (null == paramASN1Encodable)
      throw new NullPointerException("'element' cannot be null"); 
    this.elements = new ASN1Encodable[] { paramASN1Encodable };
  }
  
  protected ASN1Sequence(ASN1EncodableVector paramASN1EncodableVector) {
    if (null == paramASN1EncodableVector)
      throw new NullPointerException("'elementVector' cannot be null"); 
    this.elements = paramASN1EncodableVector.takeElements();
  }
  
  protected ASN1Sequence(ASN1Encodable[] paramArrayOfASN1Encodable) {
    if (Arrays.isNullOrContainsNull((Object[])paramArrayOfASN1Encodable))
      throw new NullPointerException("'elements' cannot be null, or contain null"); 
    this.elements = ASN1EncodableVector.cloneElements(paramArrayOfASN1Encodable);
  }
  
  ASN1Sequence(ASN1Encodable[] paramArrayOfASN1Encodable, boolean paramBoolean) {
    this.elements = paramBoolean ? ASN1EncodableVector.cloneElements(paramArrayOfASN1Encodable) : paramArrayOfASN1Encodable;
  }
  
  public ASN1Encodable[] toArray() {
    return ASN1EncodableVector.cloneElements(this.elements);
  }
  
  ASN1Encodable[] toArrayInternal() {
    return this.elements;
  }
  
  public Enumeration getObjects() {
    return (Enumeration)new Object(this);
  }
  
  public ASN1SequenceParser parser() {
    int i = size();
    return (ASN1SequenceParser)new Object(this, i);
  }
  
  public ASN1Encodable getObjectAt(int paramInt) {
    return this.elements[paramInt];
  }
  
  public int size() {
    return this.elements.length;
  }
  
  public int hashCode() {
    int i = this.elements.length;
    int j = i + 1;
    while (--i >= 0) {
      j *= 257;
      j ^= this.elements[i].toASN1Primitive().hashCode();
    } 
    return j;
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1Sequence))
      return false; 
    org.bouncycastle.asn1.ASN1Sequence aSN1Sequence = (org.bouncycastle.asn1.ASN1Sequence)paramASN1Primitive;
    int i = size();
    if (aSN1Sequence.size() != i)
      return false; 
    for (byte b = 0; b < i; b++) {
      ASN1Primitive aSN1Primitive1 = this.elements[b].toASN1Primitive();
      ASN1Primitive aSN1Primitive2 = aSN1Sequence.elements[b].toASN1Primitive();
      if (aSN1Primitive1 != aSN1Primitive2 && !aSN1Primitive1.asn1Equals(aSN1Primitive2))
        return false; 
    } 
    return true;
  }
  
  ASN1Primitive toDERObject() {
    return new DERSequence(this.elements, false);
  }
  
  ASN1Primitive toDLObject() {
    return new DLSequence(this.elements, false);
  }
  
  abstract ASN1BitString toASN1BitString();
  
  abstract ASN1External toASN1External();
  
  abstract ASN1OctetString toASN1OctetString();
  
  abstract ASN1Set toASN1Set();
  
  boolean encodeConstructed() {
    return true;
  }
  
  public String toString() {
    int i = size();
    if (0 == i)
      return "[]"; 
    StringBuffer stringBuffer = new StringBuffer();
    stringBuffer.append('[');
    byte b = 0;
    while (true) {
      stringBuffer.append(this.elements[b]);
      if (++b >= i)
        break; 
      stringBuffer.append(", ");
    } 
    stringBuffer.append(']');
    return stringBuffer.toString();
  }
  
  public Iterator<ASN1Encodable> iterator() {
    return new Arrays.Iterator<>(this.elements);
  }
  
  ASN1BitString[] getConstructedBitStrings() {
    int i = size();
    ASN1BitString[] arrayOfASN1BitString = new ASN1BitString[i];
    for (byte b = 0; b < i; b++)
      arrayOfASN1BitString[b] = ASN1BitString.getInstance(this.elements[b]); 
    return arrayOfASN1BitString;
  }
  
  ASN1OctetString[] getConstructedOctetStrings() {
    int i = size();
    ASN1OctetString[] arrayOfASN1OctetString = new ASN1OctetString[i];
    for (byte b = 0; b < i; b++)
      arrayOfASN1OctetString[b] = ASN1OctetString.getInstance(this.elements[b]); 
    return arrayOfASN1OctetString;
  }
}
