package org.bouncycastle.jcajce.spec;

import java.security.spec.ECParameterSpec;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.util.Arrays;

public class DSTU4145ParameterSpec extends ECParameterSpec {
  private final byte[] dke;
  
  private final ECDomainParameters parameters;
  
  public DSTU4145ParameterSpec(ECDomainParameters paramECDomainParameters) {
    this(paramECDomainParameters, EC5Util.convertToSpec(paramECDomainParameters), DSTU4145Params.getDefaultDKE());
  }
  
  private DSTU4145ParameterSpec(ECDomainParameters paramECDomainParameters, ECParameterSpec paramECParameterSpec, byte[] paramArrayOfbyte) {
    super(paramECParameterSpec.getCurve(), paramECParameterSpec.getGenerator(), paramECParameterSpec.getOrder(), paramECParameterSpec.getCofactor());
    this.parameters = paramECDomainParameters;
    this.dke = Arrays.clone(paramArrayOfbyte);
  }
  
  public byte[] getDKE() {
    return Arrays.clone(this.dke);
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject instanceof DSTU4145ParameterSpec) {
      DSTU4145ParameterSpec dSTU4145ParameterSpec = (DSTU4145ParameterSpec)paramObject;
      return this.parameters.equals(dSTU4145ParameterSpec.parameters);
    } 
    return false;
  }
  
  public int hashCode() {
    return this.parameters.hashCode();
  }
}
