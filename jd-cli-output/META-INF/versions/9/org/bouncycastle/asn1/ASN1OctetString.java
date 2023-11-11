package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public abstract class ASN1OctetString extends ASN1Primitive implements ASN1OctetStringParser {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1OctetString.class, 4);
  
  public static org.bouncycastle.asn1.ASN1OctetString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1OctetString)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public static org.bouncycastle.asn1.ASN1OctetString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1OctetString)
      return (org.bouncycastle.asn1.ASN1OctetString)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1OctetString)
        return (org.bouncycastle.asn1.ASN1OctetString)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (org.bouncycastle.asn1.ASN1OctetString)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct OCTET STRING from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  static final byte[] EMPTY_OCTETS = new byte[0];
  
  byte[] string;
  
  public ASN1OctetString(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      throw new NullPointerException("'string' cannot be null"); 
    this.string = paramArrayOfbyte;
  }
  
  public InputStream getOctetStream() {
    return new ByteArrayInputStream(this.string);
  }
  
  public ASN1OctetStringParser parser() {
    return this;
  }
  
  public byte[] getOctets() {
    return this.string;
  }
  
  public int hashCode() {
    return Arrays.hashCode(getOctets());
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1OctetString))
      return false; 
    org.bouncycastle.asn1.ASN1OctetString aSN1OctetString = (org.bouncycastle.asn1.ASN1OctetString)paramASN1Primitive;
    return Arrays.areEqual(this.string, aSN1OctetString.string);
  }
  
  public ASN1Primitive getLoadedObject() {
    return toASN1Primitive();
  }
  
  ASN1Primitive toDERObject() {
    return new DEROctetString(this.string);
  }
  
  ASN1Primitive toDLObject() {
    return new DEROctetString(this.string);
  }
  
  public String toString() {
    return "#" + Strings.fromByteArray(Hex.encode(this.string));
  }
  
  static org.bouncycastle.asn1.ASN1OctetString createPrimitive(byte[] paramArrayOfbyte) {
    return new DEROctetString(paramArrayOfbyte);
  }
}
