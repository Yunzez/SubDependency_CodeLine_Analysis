package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;

public class EdDSAParameterSpec implements AlgorithmParameterSpec {
  public static final String Ed25519 = "Ed25519";
  
  public static final String Ed448 = "Ed448";
  
  private final String curveName;
  
  public EdDSAParameterSpec(String paramString) {
    if (paramString.equalsIgnoreCase("Ed25519")) {
      this.curveName = "Ed25519";
    } else if (paramString.equalsIgnoreCase("Ed448")) {
      this.curveName = "Ed448";
    } else if (paramString.equals(EdECObjectIdentifiers.id_Ed25519.getId())) {
      this.curveName = "Ed25519";
    } else if (paramString.equals(EdECObjectIdentifiers.id_Ed448.getId())) {
      this.curveName = "Ed448";
    } else {
      throw new IllegalArgumentException("unrecognized curve name: " + paramString);
    } 
  }
  
  public String getCurveName() {
    return this.curveName;
  }
}
