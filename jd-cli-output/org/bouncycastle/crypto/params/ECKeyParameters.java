package org.bouncycastle.crypto.params;

public class ECKeyParameters extends AsymmetricKeyParameter {
  private final ECDomainParameters parameters;
  
  protected ECKeyParameters(boolean paramBoolean, ECDomainParameters paramECDomainParameters) {
    super(paramBoolean);
    if (null == paramECDomainParameters)
      throw new NullPointerException("'parameters' cannot be null"); 
    this.parameters = paramECDomainParameters;
  }
  
  public ECDomainParameters getParameters() {
    return this.parameters;
  }
}
