package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Strings;

public class GeneralNames extends ASN1Object {
  private final GeneralName[] names;
  
  private static GeneralName[] copy(GeneralName[] paramArrayOfGeneralName) {
    GeneralName[] arrayOfGeneralName = new GeneralName[paramArrayOfGeneralName.length];
    System.arraycopy(paramArrayOfGeneralName, 0, arrayOfGeneralName, 0, paramArrayOfGeneralName.length);
    return arrayOfGeneralName;
  }
  
  public static GeneralNames getInstance(Object paramObject) {
    return (paramObject instanceof GeneralNames) ? (GeneralNames)paramObject : ((paramObject != null) ? new GeneralNames(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public static GeneralNames getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return new GeneralNames(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static GeneralNames fromExtensions(Extensions paramExtensions, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return getInstance(Extensions.getExtensionParsedValue(paramExtensions, paramASN1ObjectIdentifier));
  }
  
  public GeneralNames(GeneralName paramGeneralName) {
    this.names = new GeneralName[] { paramGeneralName };
  }
  
  public GeneralNames(GeneralName[] paramArrayOfGeneralName) {
    this.names = copy(paramArrayOfGeneralName);
  }
  
  private GeneralNames(ASN1Sequence paramASN1Sequence) {
    this.names = new GeneralName[paramASN1Sequence.size()];
    for (byte b = 0; b != paramASN1Sequence.size(); b++)
      this.names[b] = GeneralName.getInstance(paramASN1Sequence.getObjectAt(b)); 
  }
  
  public GeneralName[] getNames() {
    return copy(this.names);
  }
  
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence((ASN1Encodable[])this.names);
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append("GeneralNames:");
    stringBuffer.append(str);
    for (byte b = 0; b != this.names.length; b++) {
      stringBuffer.append("    ");
      stringBuffer.append(this.names[b]);
      stringBuffer.append(str);
    } 
    return stringBuffer.toString();
  }
}
