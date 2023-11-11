package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECCurve;

class ECUtils {
  static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey paramPublicKey) throws InvalidKeyException {
    return (paramPublicKey instanceof BCECPublicKey) ? ((BCECPublicKey)paramPublicKey).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(paramPublicKey);
  }
  
  static X9ECParameters getDomainParametersFromGenSpec(ECGenParameterSpec paramECGenParameterSpec, ProviderConfiguration paramProviderConfiguration) {
    return getDomainParametersFromName(paramECGenParameterSpec.getName(), paramProviderConfiguration);
  }
  
  static X9ECParameters getDomainParametersFromName(String paramString, ProviderConfiguration paramProviderConfiguration) {
    if (null == paramString || paramString.length() < 1)
      return null; 
    int i = paramString.indexOf(' ');
    if (i > 0)
      paramString = paramString.substring(i + 1); 
    ASN1ObjectIdentifier aSN1ObjectIdentifier = getOID(paramString);
    if (null == aSN1ObjectIdentifier)
      return ECUtil.getNamedCurveByName(paramString); 
    X9ECParameters x9ECParameters = ECUtil.getNamedCurveByOid(aSN1ObjectIdentifier);
    if (null == x9ECParameters && null != paramProviderConfiguration) {
      Map map = paramProviderConfiguration.getAdditionalECParameters();
      x9ECParameters = (X9ECParameters)map.get(aSN1ObjectIdentifier);
    } 
    return x9ECParameters;
  }
  
  static X962Parameters getDomainParametersFromName(ECParameterSpec paramECParameterSpec, boolean paramBoolean) {
    X962Parameters x962Parameters;
    if (paramECParameterSpec instanceof ECNamedCurveSpec) {
      ASN1ObjectIdentifier aSN1ObjectIdentifier = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)paramECParameterSpec).getName());
      if (aSN1ObjectIdentifier == null)
        aSN1ObjectIdentifier = new ASN1ObjectIdentifier(((ECNamedCurveSpec)paramECParameterSpec).getName()); 
      x962Parameters = new X962Parameters(aSN1ObjectIdentifier);
    } else if (paramECParameterSpec == null) {
      x962Parameters = new X962Parameters(DERNull.INSTANCE);
    } else {
      ECCurve eCCurve = EC5Util.convertCurve(paramECParameterSpec.getCurve());
      X9ECParameters x9ECParameters = new X9ECParameters(eCCurve, new X9ECPoint(EC5Util.convertPoint(eCCurve, paramECParameterSpec.getGenerator()), paramBoolean), paramECParameterSpec.getOrder(), BigInteger.valueOf(paramECParameterSpec.getCofactor()), paramECParameterSpec.getCurve().getSeed());
      x962Parameters = new X962Parameters(x9ECParameters);
    } 
    return x962Parameters;
  }
  
  private static ASN1ObjectIdentifier getOID(String paramString) {
    char c = paramString.charAt(0);
    if (c >= '0' && c <= '2')
      try {
        return new ASN1ObjectIdentifier(paramString);
      } catch (Exception exception) {} 
    return null;
  }
}
