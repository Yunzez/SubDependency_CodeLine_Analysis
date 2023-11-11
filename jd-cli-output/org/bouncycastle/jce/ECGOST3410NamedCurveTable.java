package org.bouncycastle.jce;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class ECGOST3410NamedCurveTable {
  public static ECNamedCurveParameterSpec getParameterSpec(String paramString) {
    X9ECParameters x9ECParameters = ECGOST3410NamedCurves.getByNameX9(paramString);
    if (x9ECParameters == null)
      try {
        x9ECParameters = ECGOST3410NamedCurves.getByOIDX9(new ASN1ObjectIdentifier(paramString));
      } catch (IllegalArgumentException illegalArgumentException) {
        return null;
      }  
    return (x9ECParameters == null) ? null : new ECNamedCurveParameterSpec(paramString, x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
  }
  
  public static Enumeration getNames() {
    return ECGOST3410NamedCurves.getNames();
  }
}
