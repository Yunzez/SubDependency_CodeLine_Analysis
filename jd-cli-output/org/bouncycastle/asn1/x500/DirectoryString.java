package org.bouncycastle.asn1.x500;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1T61String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1UniversalString;
import org.bouncycastle.asn1.DERUTF8String;

public class DirectoryString extends ASN1Object implements ASN1Choice, ASN1String {
  private ASN1String string;
  
  public static DirectoryString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DirectoryString)
      return (DirectoryString)paramObject; 
    if (paramObject instanceof ASN1T61String)
      return new DirectoryString((ASN1T61String)paramObject); 
    if (paramObject instanceof ASN1PrintableString)
      return new DirectoryString((ASN1PrintableString)paramObject); 
    if (paramObject instanceof ASN1UniversalString)
      return new DirectoryString((ASN1UniversalString)paramObject); 
    if (paramObject instanceof ASN1UTF8String)
      return new DirectoryString((ASN1UTF8String)paramObject); 
    if (paramObject instanceof ASN1BMPString)
      return new DirectoryString((ASN1BMPString)paramObject); 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DirectoryString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    if (!paramBoolean)
      throw new IllegalArgumentException("choice item must be explicitly tagged"); 
    return getInstance(paramASN1TaggedObject.getObject());
  }
  
  private DirectoryString(ASN1T61String paramASN1T61String) {
    this.string = paramASN1T61String;
  }
  
  private DirectoryString(ASN1PrintableString paramASN1PrintableString) {
    this.string = paramASN1PrintableString;
  }
  
  private DirectoryString(ASN1UniversalString paramASN1UniversalString) {
    this.string = paramASN1UniversalString;
  }
  
  private DirectoryString(ASN1UTF8String paramASN1UTF8String) {
    this.string = paramASN1UTF8String;
  }
  
  private DirectoryString(ASN1BMPString paramASN1BMPString) {
    this.string = paramASN1BMPString;
  }
  
  public DirectoryString(String paramString) {
    this.string = new DERUTF8String(paramString);
  }
  
  public String getString() {
    return this.string.getString();
  }
  
  public String toString() {
    return this.string.getString();
  }
  
  public ASN1Primitive toASN1Primitive() {
    return ((ASN1Encodable)this.string).toASN1Primitive();
  }
}
