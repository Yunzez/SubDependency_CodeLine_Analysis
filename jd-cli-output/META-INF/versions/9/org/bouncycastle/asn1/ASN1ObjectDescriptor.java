package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GraphicString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;

public final class ASN1ObjectDescriptor extends ASN1Primitive {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1ObjectDescriptor.class, 7);
  
  private final ASN1GraphicString baseGraphicString;
  
  public static org.bouncycastle.asn1.ASN1ObjectDescriptor getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1ObjectDescriptor)
      return (org.bouncycastle.asn1.ASN1ObjectDescriptor)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1ObjectDescriptor)
        return (org.bouncycastle.asn1.ASN1ObjectDescriptor)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (org.bouncycastle.asn1.ASN1ObjectDescriptor)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct object descriptor from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1ObjectDescriptor getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1ObjectDescriptor)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
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
    return (aSN1GraphicString == this.baseGraphicString) ? this : new org.bouncycastle.asn1.ASN1ObjectDescriptor(aSN1GraphicString);
  }
  
  ASN1Primitive toDLObject() {
    ASN1GraphicString aSN1GraphicString = (ASN1GraphicString)this.baseGraphicString.toDLObject();
    return (aSN1GraphicString == this.baseGraphicString) ? this : new org.bouncycastle.asn1.ASN1ObjectDescriptor(aSN1GraphicString);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1ObjectDescriptor))
      return false; 
    org.bouncycastle.asn1.ASN1ObjectDescriptor aSN1ObjectDescriptor = (org.bouncycastle.asn1.ASN1ObjectDescriptor)paramASN1Primitive;
    return this.baseGraphicString.asn1Equals(aSN1ObjectDescriptor.baseGraphicString);
  }
  
  public int hashCode() {
    return this.baseGraphicString.hashCode() ^ 0xFFFFFFFF;
  }
  
  static org.bouncycastle.asn1.ASN1ObjectDescriptor createPrimitive(byte[] paramArrayOfbyte) {
    return new org.bouncycastle.asn1.ASN1ObjectDescriptor(ASN1GraphicString.createPrimitive(paramArrayOfbyte));
  }
}
