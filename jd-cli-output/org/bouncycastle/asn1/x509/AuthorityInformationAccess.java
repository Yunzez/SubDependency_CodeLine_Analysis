package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class AuthorityInformationAccess extends ASN1Object {
  private AccessDescription[] descriptions;
  
  private static AccessDescription[] copy(AccessDescription[] paramArrayOfAccessDescription) {
    AccessDescription[] arrayOfAccessDescription = new AccessDescription[paramArrayOfAccessDescription.length];
    System.arraycopy(paramArrayOfAccessDescription, 0, arrayOfAccessDescription, 0, paramArrayOfAccessDescription.length);
    return arrayOfAccessDescription;
  }
  
  public static AuthorityInformationAccess getInstance(Object paramObject) {
    return (paramObject instanceof AuthorityInformationAccess) ? (AuthorityInformationAccess)paramObject : ((paramObject != null) ? new AuthorityInformationAccess(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public static AuthorityInformationAccess fromExtensions(Extensions paramExtensions) {
    return getInstance(Extensions.getExtensionParsedValue(paramExtensions, Extension.authorityInfoAccess));
  }
  
  private AuthorityInformationAccess(ASN1Sequence paramASN1Sequence) {
    if (paramASN1Sequence.size() < 1)
      throw new IllegalArgumentException("sequence may not be empty"); 
    this.descriptions = new AccessDescription[paramASN1Sequence.size()];
    for (byte b = 0; b != paramASN1Sequence.size(); b++)
      this.descriptions[b] = AccessDescription.getInstance(paramASN1Sequence.getObjectAt(b)); 
  }
  
  public AuthorityInformationAccess(AccessDescription paramAccessDescription) {
    this.descriptions = new AccessDescription[] { paramAccessDescription };
  }
  
  public AuthorityInformationAccess(AccessDescription[] paramArrayOfAccessDescription) {
    this.descriptions = copy(paramArrayOfAccessDescription);
  }
  
  public AuthorityInformationAccess(ASN1ObjectIdentifier paramASN1ObjectIdentifier, GeneralName paramGeneralName) {
    this(new AccessDescription(paramASN1ObjectIdentifier, paramGeneralName));
  }
  
  public AccessDescription[] getAccessDescriptions() {
    return copy(this.descriptions);
  }
  
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence((ASN1Encodable[])this.descriptions);
  }
  
  public String toString() {
    return "AuthorityInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")";
  }
}
