package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

public class DHExtendedPrivateKeySpec extends DHPrivateKeySpec {
  private final DHParameterSpec params;
  
  public DHExtendedPrivateKeySpec(BigInteger paramBigInteger, DHParameterSpec paramDHParameterSpec) {
    super(paramBigInteger, paramDHParameterSpec.getP(), paramDHParameterSpec.getG());
    this.params = paramDHParameterSpec;
  }
  
  public DHParameterSpec getParams() {
    return this.params;
  }
}
