package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SPHINCSPlusKeyParameters extends AsymmetricKeyParameter {
  final SPHINCSPlusParameters parameters;
  
  protected SPHINCSPlusKeyParameters(boolean paramBoolean, SPHINCSPlusParameters paramSPHINCSPlusParameters) {
    super(paramBoolean);
    this.parameters = paramSPHINCSPlusParameters;
  }
  
  public SPHINCSPlusParameters getParameters() {
    return this.parameters;
  }
}
