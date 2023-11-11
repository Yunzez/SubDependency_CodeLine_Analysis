package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

public class DHExtendedPublicKeySpec extends DHPublicKeySpec {
  private final DHParameterSpec params;
  
  public DHExtendedPublicKeySpec(BigInteger paramBigInteger, DHParameterSpec paramDHParameterSpec) {
    super(paramBigInteger, paramDHParameterSpec.getP(), paramDHParameterSpec.getG());
    this.params = paramDHParameterSpec;
  }
  
  public DHParameterSpec getParams() {
    return this.params;
  }
}
