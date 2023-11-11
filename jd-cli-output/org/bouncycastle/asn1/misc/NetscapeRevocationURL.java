package org.bouncycastle.asn1.misc;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.DERIA5String;

public class NetscapeRevocationURL extends DERIA5String {
  public NetscapeRevocationURL(ASN1IA5String paramASN1IA5String) {
    super(paramASN1IA5String.getString());
  }
  
  public String toString() {
    return "NetscapeRevocationURL: " + getString();
  }
}
