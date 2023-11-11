package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.util.Objects;

public abstract class ASN1External extends ASN1Primitive {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1External.class, 8) {
      ASN1Primitive fromImplicitConstructed(ASN1Sequence param1ASN1Sequence) {
        return param1ASN1Sequence.toASN1External();
      }
    };
  
  ASN1ObjectIdentifier directReference;
  
  ASN1Integer indirectReference;
  
  ASN1Primitive dataValueDescriptor;
  
  int encoding;
  
  ASN1Primitive externalContent;
  
  public static ASN1External getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1External)
      return (ASN1External)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1External)
        return (ASN1External)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (ASN1External)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct external from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1External getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1External)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  ASN1External(ASN1Sequence paramASN1Sequence) {
    byte b = 0;
    ASN1Primitive aSN1Primitive = getObjFromSequence(paramASN1Sequence, b);
    if (aSN1Primitive instanceof ASN1ObjectIdentifier) {
      this.directReference = (ASN1ObjectIdentifier)aSN1Primitive;
      aSN1Primitive = getObjFromSequence(paramASN1Sequence, ++b);
    } 
    if (aSN1Primitive instanceof ASN1Integer) {
      this.indirectReference = (ASN1Integer)aSN1Primitive;
      aSN1Primitive = getObjFromSequence(paramASN1Sequence, ++b);
    } 
    if (!(aSN1Primitive instanceof ASN1TaggedObject)) {
      this.dataValueDescriptor = aSN1Primitive;
      aSN1Primitive = getObjFromSequence(paramASN1Sequence, ++b);
    } 
    if (paramASN1Sequence.size() != b + 1)
      throw new IllegalArgumentException("input sequence too large"); 
    if (!(aSN1Primitive instanceof ASN1TaggedObject))
      throw new IllegalArgumentException("No tagged object found in sequence. Structure doesn't seem to be of type External"); 
    ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject)aSN1Primitive;
    this.encoding = checkEncoding(aSN1TaggedObject.getTagNo());
    this.externalContent = getExternalContent(aSN1TaggedObject);
  }
  
  ASN1External(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Integer paramASN1Integer, ASN1Primitive paramASN1Primitive, DERTaggedObject paramDERTaggedObject) {
    this.directReference = paramASN1ObjectIdentifier;
    this.indirectReference = paramASN1Integer;
    this.dataValueDescriptor = paramASN1Primitive;
    this.encoding = checkEncoding(paramDERTaggedObject.getTagNo());
    this.externalContent = getExternalContent(paramDERTaggedObject);
  }
  
  ASN1External(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Integer paramASN1Integer, ASN1Primitive paramASN1Primitive1, int paramInt, ASN1Primitive paramASN1Primitive2) {
    this.directReference = paramASN1ObjectIdentifier;
    this.indirectReference = paramASN1Integer;
    this.dataValueDescriptor = paramASN1Primitive1;
    this.encoding = checkEncoding(paramInt);
    this.externalContent = checkExternalContent(paramInt, paramASN1Primitive2);
  }
  
  abstract ASN1Sequence buildSequence();
  
  int encodedLength(boolean paramBoolean) throws IOException {
    return buildSequence().encodedLength(paramBoolean);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeIdentifier(paramBoolean, 40);
    buildSequence().encode(paramASN1OutputStream, false);
  }
  
  ASN1Primitive toDERObject() {
    return new DERExternal(this.directReference, this.indirectReference, this.dataValueDescriptor, this.encoding, this.externalContent);
  }
  
  ASN1Primitive toDLObject() {
    return new DLExternal(this.directReference, this.indirectReference, this.dataValueDescriptor, this.encoding, this.externalContent);
  }
  
  public int hashCode() {
    return Objects.hashCode(this.directReference) ^ Objects.hashCode(this.indirectReference) ^ Objects.hashCode(this.dataValueDescriptor) ^ this.encoding ^ this.externalContent.hashCode();
  }
  
  boolean encodeConstructed() {
    return true;
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (this == paramASN1Primitive)
      return true; 
    if (!(paramASN1Primitive instanceof ASN1External))
      return false; 
    ASN1External aSN1External = (ASN1External)paramASN1Primitive;
    return (Objects.areEqual(this.directReference, aSN1External.directReference) && Objects.areEqual(this.indirectReference, aSN1External.indirectReference) && Objects.areEqual(this.dataValueDescriptor, aSN1External.dataValueDescriptor) && this.encoding == aSN1External.encoding && this.externalContent.equals(aSN1External.externalContent));
  }
  
  public ASN1Primitive getDataValueDescriptor() {
    return this.dataValueDescriptor;
  }
  
  public ASN1ObjectIdentifier getDirectReference() {
    return this.directReference;
  }
  
  public int getEncoding() {
    return this.encoding;
  }
  
  public ASN1Primitive getExternalContent() {
    return this.externalContent;
  }
  
  public ASN1Integer getIndirectReference() {
    return this.indirectReference;
  }
  
  private static int checkEncoding(int paramInt) {
    if (paramInt < 0 || paramInt > 2)
      throw new IllegalArgumentException("invalid encoding value: " + paramInt); 
    return paramInt;
  }
  
  private static ASN1Primitive checkExternalContent(int paramInt, ASN1Primitive paramASN1Primitive) {
    switch (paramInt) {
      case 1:
        return ASN1OctetString.TYPE.checkedCast(paramASN1Primitive);
      case 2:
        return ASN1BitString.TYPE.checkedCast(paramASN1Primitive);
    } 
    return paramASN1Primitive;
  }
  
  private static ASN1Primitive getExternalContent(ASN1TaggedObject paramASN1TaggedObject) {
    int i = paramASN1TaggedObject.getTagClass();
    int j = paramASN1TaggedObject.getTagNo();
    if (128 != i)
      throw new IllegalArgumentException("invalid tag: " + ASN1Util.getTagText(i, j)); 
    switch (j) {
      case 0:
        return paramASN1TaggedObject.getExplicitBaseObject().toASN1Primitive();
      case 1:
        return ASN1OctetString.getInstance(paramASN1TaggedObject, false);
      case 2:
        return ASN1BitString.getInstance(paramASN1TaggedObject, false);
    } 
    throw new IllegalArgumentException("invalid tag: " + ASN1Util.getTagText(i, j));
  }
  
  private static ASN1Primitive getObjFromSequence(ASN1Sequence paramASN1Sequence, int paramInt) {
    if (paramASN1Sequence.size() <= paramInt)
      throw new IllegalArgumentException("too few objects in input sequence"); 
    return paramASN1Sequence.getObjectAt(paramInt).toASN1Primitive();
  }
}
