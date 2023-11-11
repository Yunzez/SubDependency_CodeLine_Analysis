package org.bouncycastle.asn1.x509.qualified;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.DERPrintableString;

public class Iso4217CurrencyCode extends ASN1Object implements ASN1Choice {
  final int ALPHABETIC_MAXSIZE = 3;
  
  final int NUMERIC_MINSIZE = 1;
  
  final int NUMERIC_MAXSIZE = 999;
  
  ASN1Encodable obj;
  
  int numeric;
  
  public static Iso4217CurrencyCode getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof Iso4217CurrencyCode)
      return (Iso4217CurrencyCode)paramObject; 
    if (paramObject instanceof ASN1Integer) {
      ASN1Integer aSN1Integer = ASN1Integer.getInstance(paramObject);
      int i = aSN1Integer.intValueExact();
      return new Iso4217CurrencyCode(i);
    } 
    if (paramObject instanceof ASN1PrintableString) {
      ASN1PrintableString aSN1PrintableString = ASN1PrintableString.getInstance(paramObject);
      return new Iso4217CurrencyCode(aSN1PrintableString.getString());
    } 
    throw new IllegalArgumentException("unknown object in getInstance");
  }
  
  public Iso4217CurrencyCode(int paramInt) {
    if (paramInt > 999 || paramInt < 1)
      throw new IllegalArgumentException("wrong size in numeric code : not in (1..999)"); 
    this.obj = new ASN1Integer(paramInt);
  }
  
  public Iso4217CurrencyCode(String paramString) {
    if (paramString.length() > 3)
      throw new IllegalArgumentException("wrong size in alphabetic code : max size is 3"); 
    this.obj = new DERPrintableString(paramString);
  }
  
  public boolean isAlphabetic() {
    return this.obj instanceof ASN1PrintableString;
  }
  
  public String getAlphabetic() {
    return ((ASN1PrintableString)this.obj).getString();
  }
  
  public int getNumeric() {
    return ((ASN1Integer)this.obj).intValueExact();
  }
  
  public ASN1Primitive toASN1Primitive() {
    return this.obj.toASN1Primitive();
  }
}
