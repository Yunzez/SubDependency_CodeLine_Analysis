package org.bouncycastle.jcajce.provider.config;

import java.security.spec.DSAParameterSpec;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

public interface ProviderConfiguration {
  ECParameterSpec getEcImplicitlyCa();
  
  DHParameterSpec getDHDefaultParameters(int paramInt);
  
  DSAParameterSpec getDSADefaultParameters(int paramInt);
  
  Set getAcceptableNamedCurves();
  
  Map getAdditionalECParameters();
}
