package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;

public abstract class ASN1Set extends ASN1Primitive implements Iterable<ASN1Encodable> {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1Set.class, 17);
  
  protected final ASN1Encodable[] elements;
  
  protected final boolean isSorted;
  
  public static org.bouncycastle.asn1.ASN1Set getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1Set)
      return (org.bouncycastle.asn1.ASN1Set)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1Set)
        return (org.bouncycastle.asn1.ASN1Set)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (org.bouncycastle.asn1.ASN1Set)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct set from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("unknown object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1Set getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1Set)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  protected ASN1Set() {
    this.elements = ASN1EncodableVector.EMPTY_ELEMENTS;
    this.isSorted = true;
  }
  
  protected ASN1Set(ASN1Encodable paramASN1Encodable) {
    if (null == paramASN1Encodable)
      throw new NullPointerException("'element' cannot be null"); 
    this.elements = new ASN1Encodable[] { paramASN1Encodable };
    this.isSorted = true;
  }
  
  protected ASN1Set(ASN1EncodableVector paramASN1EncodableVector, boolean paramBoolean) {
    ASN1Encodable[] arrayOfASN1Encodable;
    if (null == paramASN1EncodableVector)
      throw new NullPointerException("'elementVector' cannot be null"); 
    if (paramBoolean && paramASN1EncodableVector.size() >= 2) {
      arrayOfASN1Encodable = paramASN1EncodableVector.copyElements();
      sort(arrayOfASN1Encodable);
    } else {
      arrayOfASN1Encodable = paramASN1EncodableVector.takeElements();
    } 
    this.elements = arrayOfASN1Encodable;
    this.isSorted = (paramBoolean || arrayOfASN1Encodable.length < 2);
  }
  
  protected ASN1Set(ASN1Encodable[] paramArrayOfASN1Encodable, boolean paramBoolean) {
    if (Arrays.isNullOrContainsNull((Object[])paramArrayOfASN1Encodable))
      throw new NullPointerException("'elements' cannot be null, or contain null"); 
    ASN1Encodable[] arrayOfASN1Encodable = ASN1EncodableVector.cloneElements(paramArrayOfASN1Encodable);
    if (paramBoolean && arrayOfASN1Encodable.length >= 2)
      sort(arrayOfASN1Encodable); 
    this.elements = arrayOfASN1Encodable;
    this.isSorted = (paramBoolean || arrayOfASN1Encodable.length < 2);
  }
  
  ASN1Set(boolean paramBoolean, ASN1Encodable[] paramArrayOfASN1Encodable) {
    this.elements = paramArrayOfASN1Encodable;
    this.isSorted = (paramBoolean || paramArrayOfASN1Encodable.length < 2);
  }
  
  public Enumeration getObjects() {
    return (Enumeration)new Object(this);
  }
  
  public ASN1Encodable getObjectAt(int paramInt) {
    return this.elements[paramInt];
  }
  
  public int size() {
    return this.elements.length;
  }
  
  public ASN1Encodable[] toArray() {
    return ASN1EncodableVector.cloneElements(this.elements);
  }
  
  public ASN1SetParser parser() {
    int i = size();
    return (ASN1SetParser)new Object(this, i);
  }
  
  public int hashCode() {
    int i = this.elements.length;
    int j = i + 1;
    while (--i >= 0)
      j += this.elements[i].toASN1Primitive().hashCode(); 
    return j;
  }
  
  ASN1Primitive toDERObject() {
    ASN1Encodable[] arrayOfASN1Encodable;
    if (this.isSorted) {
      arrayOfASN1Encodable = this.elements;
    } else {
      arrayOfASN1Encodable = (ASN1Encodable[])this.elements.clone();
      sort(arrayOfASN1Encodable);
    } 
    return new DERSet(true, arrayOfASN1Encodable);
  }
  
  ASN1Primitive toDLObject() {
    return new DLSet(this.isSorted, this.elements);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1Set))
      return false; 
    org.bouncycastle.asn1.ASN1Set aSN1Set = (org.bouncycastle.asn1.ASN1Set)paramASN1Primitive;
    int i = size();
    if (aSN1Set.size() != i)
      return false; 
    DERSet dERSet1 = (DERSet)toDERObject();
    DERSet dERSet2 = (DERSet)aSN1Set.toDERObject();
    for (byte b = 0; b < i; b++) {
      ASN1Primitive aSN1Primitive1 = dERSet1.elements[b].toASN1Primitive();
      ASN1Primitive aSN1Primitive2 = dERSet2.elements[b].toASN1Primitive();
      if (aSN1Primitive1 != aSN1Primitive2 && !aSN1Primitive1.asn1Equals(aSN1Primitive2))
        return false; 
    } 
    return true;
  }
  
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
    return new Arrays.Iterator<>(toArray());
  }
  
  private static byte[] getDEREncoded(ASN1Encodable paramASN1Encodable) {
    try {
      return paramASN1Encodable.toASN1Primitive().getEncoded("DER");
    } catch (IOException iOException) {
      throw new IllegalArgumentException("cannot encode object added to SET");
    } 
  }
  
  private static boolean lessThanOrEqual(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    int i = paramArrayOfbyte1[0] & 0xFFFFFFDF;
    int j = paramArrayOfbyte2[0] & 0xFFFFFFDF;
    if (i != j)
      return (i < j); 
    int k = Math.min(paramArrayOfbyte1.length, paramArrayOfbyte2.length) - 1;
    for (byte b = 1; b < k; b++) {
      if (paramArrayOfbyte1[b] != paramArrayOfbyte2[b])
        return ((paramArrayOfbyte1[b] & 0xFF) < (paramArrayOfbyte2[b] & 0xFF)); 
    } 
    return ((paramArrayOfbyte1[k] & 0xFF) <= (paramArrayOfbyte2[k] & 0xFF));
  }
  
  private static void sort(ASN1Encodable[] paramArrayOfASN1Encodable) {
    int i = paramArrayOfASN1Encodable.length;
    if (i < 2)
      return; 
    ASN1Encodable aSN1Encodable1 = paramArrayOfASN1Encodable[0], aSN1Encodable2 = paramArrayOfASN1Encodable[1];
    byte[] arrayOfByte1 = getDEREncoded(aSN1Encodable1), arrayOfByte2 = getDEREncoded(aSN1Encodable2);
    if (lessThanOrEqual(arrayOfByte2, arrayOfByte1)) {
      ASN1Encodable aSN1Encodable = aSN1Encodable2;
      aSN1Encodable2 = aSN1Encodable1;
      aSN1Encodable1 = aSN1Encodable;
      byte[] arrayOfByte = arrayOfByte2;
      arrayOfByte2 = arrayOfByte1;
      arrayOfByte1 = arrayOfByte;
    } 
    for (byte b = 2; b < i; b++) {
      ASN1Encodable aSN1Encodable = paramArrayOfASN1Encodable[b];
      byte[] arrayOfByte = getDEREncoded(aSN1Encodable);
      if (lessThanOrEqual(arrayOfByte2, arrayOfByte)) {
        paramArrayOfASN1Encodable[b - 2] = aSN1Encodable1;
        aSN1Encodable1 = aSN1Encodable2;
        arrayOfByte1 = arrayOfByte2;
        aSN1Encodable2 = aSN1Encodable;
        arrayOfByte2 = arrayOfByte;
      } else if (lessThanOrEqual(arrayOfByte1, arrayOfByte)) {
        paramArrayOfASN1Encodable[b - 2] = aSN1Encodable1;
        aSN1Encodable1 = aSN1Encodable;
        arrayOfByte1 = arrayOfByte;
      } else {
        int j = b - 1;
        while (--j > 0) {
          ASN1Encodable aSN1Encodable3 = paramArrayOfASN1Encodable[j - 1];
          byte[] arrayOfByte3 = getDEREncoded(aSN1Encodable3);
          if (lessThanOrEqual(arrayOfByte3, arrayOfByte))
            break; 
          paramArrayOfASN1Encodable[j] = aSN1Encodable3;
        } 
        paramArrayOfASN1Encodable[j] = aSN1Encodable;
      } 
    } 
    paramArrayOfASN1Encodable[i - 2] = aSN1Encodable1;
    paramArrayOfASN1Encodable[i - 1] = aSN1Encodable2;
  }
}
