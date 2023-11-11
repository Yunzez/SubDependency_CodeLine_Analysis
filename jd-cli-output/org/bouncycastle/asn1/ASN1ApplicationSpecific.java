package org.bouncycastle.asn1;

import java.io.IOException;

public abstract class ASN1ApplicationSpecific extends ASN1Primitive implements ASN1ApplicationSpecificParser {
  final ASN1TaggedObject taggedObject;
  
  public static ASN1ApplicationSpecific getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1ApplicationSpecific)
      return (ASN1ApplicationSpecific)paramObject; 
    if (paramObject instanceof byte[])
      try {
        return getInstance(ASN1Primitive.fromByteArray((byte[])paramObject));
      } catch (IOException iOException) {
        throw new IllegalArgumentException("Failed to construct object from byte[]: " + iOException.getMessage());
      }  
    throw new IllegalArgumentException("unknown object in getInstance: " + paramObject.getClass().getName());
  }
  
  ASN1ApplicationSpecific(ASN1TaggedObject paramASN1TaggedObject) {
    checkTagClass(paramASN1TaggedObject.getTagClass());
    this.taggedObject = paramASN1TaggedObject;
  }
  
  public int getApplicationTag() {
    return this.taggedObject.getTagNo();
  }
  
  public byte[] getContents() {
    return this.taggedObject.getContents();
  }
  
  public final ASN1Primitive getLoadedObject() {
    return this;
  }
  
  public ASN1Primitive getObject() throws IOException {
    return getEnclosedObject();
  }
  
  public ASN1Primitive getEnclosedObject() throws IOException {
    return this.taggedObject.getBaseObject().toASN1Primitive();
  }
  
  public ASN1Primitive getObject(int paramInt) throws IOException {
    return this.taggedObject.getBaseUniversal(false, paramInt);
  }
  
  public ASN1Encodable getObjectParser(int paramInt, boolean paramBoolean) throws IOException {
    throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags");
  }
  
  public ASN1Encodable parseBaseUniversal(boolean paramBoolean, int paramInt) throws IOException {
    return this.taggedObject.parseBaseUniversal(paramBoolean, paramInt);
  }
  
  public ASN1Encodable parseExplicitBaseObject() throws IOException {
    return this.taggedObject.parseExplicitBaseObject();
  }
  
  public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
    return this.taggedObject.parseExplicitBaseTagged();
  }
  
  public ASN1TaggedObjectParser parseImplicitBaseTagged(int paramInt1, int paramInt2) throws IOException {
    return this.taggedObject.parseImplicitBaseTagged(paramInt1, paramInt2);
  }
  
  public int getTagClass() {
    return 64;
  }
  
  public int getTagNo() {
    return this.taggedObject.getTagNo();
  }
  
  public boolean hasApplicationTag(int paramInt) {
    return this.taggedObject.hasTag(64, paramInt);
  }
  
  public boolean hasContextTag(int paramInt) {
    return false;
  }
  
  public boolean hasTag(int paramInt1, int paramInt2) {
    return this.taggedObject.hasTag(paramInt1, paramInt2);
  }
  
  public ASN1TaggedObject getTaggedObject() {
    return this.taggedObject;
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    ASN1TaggedObject aSN1TaggedObject;
    if (paramASN1Primitive instanceof ASN1ApplicationSpecific) {
      aSN1TaggedObject = ((ASN1ApplicationSpecific)paramASN1Primitive).taggedObject;
    } else if (paramASN1Primitive instanceof ASN1TaggedObject) {
      aSN1TaggedObject = (ASN1TaggedObject)paramASN1Primitive;
    } else {
      return false;
    } 
    return this.taggedObject.equals(aSN1TaggedObject);
  }
  
  public int hashCode() {
    return this.taggedObject.hashCode();
  }
  
  public boolean isConstructed() {
    return this.taggedObject.isConstructed();
  }
  
  public ASN1Encodable readObject() throws IOException {
    return parseExplicitBaseObject();
  }
  
  boolean encodeConstructed() {
    return this.taggedObject.encodeConstructed();
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    return this.taggedObject.encodedLength(paramBoolean);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    this.taggedObject.encode(paramASN1OutputStream, paramBoolean);
  }
  
  ASN1Primitive toDERObject() {
    return new DERApplicationSpecific((ASN1TaggedObject)this.taggedObject.toDERObject());
  }
  
  ASN1Primitive toDLObject() {
    return new DLApplicationSpecific((ASN1TaggedObject)this.taggedObject.toDLObject());
  }
  
  private static int checkTagClass(int paramInt) {
    if (64 != paramInt)
      throw new IllegalArgumentException(); 
    return paramInt;
  }
}
