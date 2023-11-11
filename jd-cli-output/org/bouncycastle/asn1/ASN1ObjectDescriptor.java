package org.bouncycastle.asn1;

import java.io.IOException;

public final class ASN1ObjectDescriptor extends ASN1Primitive {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1ObjectDescriptor.class, 7) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return new ASN1ObjectDescriptor((ASN1GraphicString)ASN1GraphicString.TYPE.fromImplicitPrimitive(param1DEROctetString));
      }
      
      ASN1Primitive fromImplicitConstructed(ASN1Sequence param1ASN1Sequence) {
        return new ASN1ObjectDescriptor((ASN1GraphicString)ASN1GraphicString.TYPE.fromImplicitConstructed(param1ASN1Sequence));
      }
    };
  
  private final ASN1GraphicString baseGraphicString;
  
  public static ASN1ObjectDescriptor getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1ObjectDescriptor)
      return (ASN1ObjectDescriptor)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1ObjectDescriptor)
        return (ASN1ObjectDescriptor)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (ASN1ObjectDescriptor)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct object descriptor from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1ObjectDescriptor getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1ObjectDescriptor)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public ASN1ObjectDescriptor(ASN1GraphicString paramASN1GraphicString) {
    if (null == paramASN1GraphicString)
      throw new NullPointerException("'baseGraphicString' cannot be null"); 
    this.baseGraphicString = paramASN1GraphicString;
  }
  
  public ASN1GraphicString getBaseGraphicString() {
    return this.baseGraphicString;
  }
  
  boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return this.baseGraphicString.encodedLength(paramBoolean);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeIdentifier(paramBoolean, 7);
    this.baseGraphicString.encode(paramASN1OutputStream, false);
  }
  
  ASN1Primitive toDERObject() {
    ASN1GraphicString aSN1GraphicString = (ASN1GraphicString)this.baseGraphicString.toDERObject();
    return (aSN1GraphicString == this.baseGraphicString) ? this : new ASN1ObjectDescriptor(aSN1GraphicString);
  }
  
  ASN1Primitive toDLObject() {
    ASN1GraphicString aSN1GraphicString = (ASN1GraphicString)this.baseGraphicString.toDLObject();
    return (aSN1GraphicString == this.baseGraphicString) ? this : new ASN1ObjectDescriptor(aSN1GraphicString);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1ObjectDescriptor))
      return false; 
    ASN1ObjectDescriptor aSN1ObjectDescriptor = (ASN1ObjectDescriptor)paramASN1Primitive;
    return this.baseGraphicString.asn1Equals(aSN1ObjectDescriptor.baseGraphicString);
  }
  
  public int hashCode() {
    return this.baseGraphicString.hashCode() ^ 0xFFFFFFFF;
  }
  
  static ASN1ObjectDescriptor createPrimitive(byte[] paramArrayOfbyte) {
    return new ASN1ObjectDescriptor(ASN1GraphicString.createPrimitive(paramArrayOfbyte));
  }
}
