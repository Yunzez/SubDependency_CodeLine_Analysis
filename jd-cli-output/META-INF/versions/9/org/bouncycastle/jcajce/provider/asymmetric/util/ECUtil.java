package META-INF.versions.9.org.bouncycastle.jcajce.provider.asymmetric.util;

import java.math.BigInteger;
import java.security.AccessController;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;

public class ECUtil {
  static int[] convertMidTerms(int[] paramArrayOfint) {
    int[] arrayOfInt = new int[3];
    if (paramArrayOfint.length == 1) {
      arrayOfInt[0] = paramArrayOfint[0];
    } else {
      if (paramArrayOfint.length != 3)
        throw new IllegalArgumentException("Only Trinomials and pentanomials supported"); 
      if (paramArrayOfint[0] < paramArrayOfint[1] && paramArrayOfint[0] < paramArrayOfint[2]) {
        arrayOfInt[0] = paramArrayOfint[0];
        if (paramArrayOfint[1] < paramArrayOfint[2]) {
          arrayOfInt[1] = paramArrayOfint[1];
          arrayOfInt[2] = paramArrayOfint[2];
        } else {
          arrayOfInt[1] = paramArrayOfint[2];
          arrayOfInt[2] = paramArrayOfint[1];
        } 
      } else if (paramArrayOfint[1] < paramArrayOfint[2]) {
        arrayOfInt[0] = paramArrayOfint[1];
        if (paramArrayOfint[0] < paramArrayOfint[2]) {
          arrayOfInt[1] = paramArrayOfint[0];
          arrayOfInt[2] = paramArrayOfint[2];
        } else {
          arrayOfInt[1] = paramArrayOfint[2];
          arrayOfInt[2] = paramArrayOfint[0];
        } 
      } else {
        arrayOfInt[0] = paramArrayOfint[2];
        if (paramArrayOfint[0] < paramArrayOfint[1]) {
          arrayOfInt[1] = paramArrayOfint[0];
          arrayOfInt[2] = paramArrayOfint[1];
        } else {
          arrayOfInt[1] = paramArrayOfint[1];
          arrayOfInt[2] = paramArrayOfint[0];
        } 
      } 
    } 
    return arrayOfInt;
  }
  
  public static ECDomainParameters getDomainParameters(ProviderConfiguration paramProviderConfiguration, ECParameterSpec paramECParameterSpec) {
    ECDomainParameters eCDomainParameters;
    if (paramECParameterSpec instanceof ECNamedCurveParameterSpec) {
      ECNamedCurveParameterSpec eCNamedCurveParameterSpec = (ECNamedCurveParameterSpec)paramECParameterSpec;
      ASN1ObjectIdentifier aSN1ObjectIdentifier = getNamedCurveOid(eCNamedCurveParameterSpec.getName());
      eCDomainParameters = new ECNamedDomainParameters(aSN1ObjectIdentifier, eCNamedCurveParameterSpec.getCurve(), eCNamedCurveParameterSpec.getG(), eCNamedCurveParameterSpec.getN(), eCNamedCurveParameterSpec.getH(), eCNamedCurveParameterSpec.getSeed());
    } else if (paramECParameterSpec == null) {
      ECParameterSpec eCParameterSpec = paramProviderConfiguration.getEcImplicitlyCa();
      eCDomainParameters = new ECDomainParameters(eCParameterSpec.getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed());
    } else {
      eCDomainParameters = new ECDomainParameters(paramECParameterSpec.getCurve(), paramECParameterSpec.getG(), paramECParameterSpec.getN(), paramECParameterSpec.getH(), paramECParameterSpec.getSeed());
    } 
    return eCDomainParameters;
  }
  
  public static ECDomainParameters getDomainParameters(ProviderConfiguration paramProviderConfiguration, X962Parameters paramX962Parameters) {
    ECDomainParameters eCDomainParameters;
    if (paramX962Parameters.isNamedCurve()) {
      ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(paramX962Parameters.getParameters());
      X9ECParameters x9ECParameters = getNamedCurveByOid(aSN1ObjectIdentifier);
      if (x9ECParameters == null) {
        Map map = paramProviderConfiguration.getAdditionalECParameters();
        x9ECParameters = (X9ECParameters)map.get(aSN1ObjectIdentifier);
      } 
      eCDomainParameters = new ECNamedDomainParameters(aSN1ObjectIdentifier, x9ECParameters);
    } else if (paramX962Parameters.isImplicitlyCA()) {
      ECParameterSpec eCParameterSpec = paramProviderConfiguration.getEcImplicitlyCa();
      eCDomainParameters = new ECDomainParameters(eCParameterSpec.getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed());
    } else {
      X9ECParameters x9ECParameters = X9ECParameters.getInstance(paramX962Parameters.getParameters());
      eCDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
    } 
    return eCDomainParameters;
  }
  
  public static AsymmetricKeyParameter generatePublicKeyParameter(PublicKey paramPublicKey) throws InvalidKeyException {
    if (paramPublicKey instanceof ECPublicKey) {
      ECPublicKey eCPublicKey = (ECPublicKey)paramPublicKey;
      ECParameterSpec eCParameterSpec = eCPublicKey.getParameters();
      return new ECPublicKeyParameters(eCPublicKey
          .getQ(), new ECDomainParameters(eCParameterSpec
            .getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed()));
    } 
    if (paramPublicKey instanceof ECPublicKey) {
      ECPublicKey eCPublicKey = (ECPublicKey)paramPublicKey;
      ECParameterSpec eCParameterSpec = EC5Util.convertSpec(eCPublicKey.getParams());
      return new ECPublicKeyParameters(
          EC5Util.convertPoint(eCPublicKey.getParams(), eCPublicKey.getW()), new ECDomainParameters(eCParameterSpec
            .getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed()));
    } 
    try {
      byte[] arrayOfByte = paramPublicKey.getEncoded();
      if (arrayOfByte == null)
        throw new InvalidKeyException("no encoding for EC public key"); 
      PublicKey publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(arrayOfByte));
      if (publicKey instanceof ECPublicKey)
        return generatePublicKeyParameter(publicKey); 
    } catch (Exception exception) {
      throw new InvalidKeyException("cannot identify EC public key: " + exception.toString());
    } 
    throw new InvalidKeyException("cannot identify EC public key.");
  }
  
  public static AsymmetricKeyParameter generatePrivateKeyParameter(PrivateKey paramPrivateKey) throws InvalidKeyException {
    if (paramPrivateKey instanceof ECPrivateKey) {
      ECPrivateKey eCPrivateKey = (ECPrivateKey)paramPrivateKey;
      ECParameterSpec eCParameterSpec = eCPrivateKey.getParameters();
      if (eCParameterSpec == null)
        eCParameterSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa(); 
      if (eCPrivateKey.getParameters() instanceof ECNamedCurveParameterSpec) {
        String str = ((ECNamedCurveParameterSpec)eCPrivateKey.getParameters()).getName();
        return new ECPrivateKeyParameters(eCPrivateKey
            .getD(), new ECNamedDomainParameters(
              ECNamedCurveTable.getOID(str), eCParameterSpec
              .getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed()));
      } 
      return new ECPrivateKeyParameters(eCPrivateKey
          .getD(), new ECDomainParameters(eCParameterSpec
            .getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed()));
    } 
    if (paramPrivateKey instanceof ECPrivateKey) {
      ECPrivateKey eCPrivateKey = (ECPrivateKey)paramPrivateKey;
      ECParameterSpec eCParameterSpec = EC5Util.convertSpec(eCPrivateKey.getParams());
      return new ECPrivateKeyParameters(eCPrivateKey
          .getS(), new ECDomainParameters(eCParameterSpec
            .getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed()));
    } 
    try {
      byte[] arrayOfByte = paramPrivateKey.getEncoded();
      if (arrayOfByte == null)
        throw new InvalidKeyException("no encoding for EC private key"); 
      PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(arrayOfByte));
      if (privateKey instanceof ECPrivateKey)
        return generatePrivateKeyParameter(privateKey); 
    } catch (Exception exception) {
      throw new InvalidKeyException("cannot identify EC private key: " + exception.toString());
    } 
    throw new InvalidKeyException("can't identify EC private key.");
  }
  
  public static int getOrderBitLength(ProviderConfiguration paramProviderConfiguration, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (paramBigInteger1 == null) {
      ECParameterSpec eCParameterSpec = paramProviderConfiguration.getEcImplicitlyCa();
      if (eCParameterSpec == null)
        return paramBigInteger2.bitLength(); 
      return eCParameterSpec.getN().bitLength();
    } 
    return paramBigInteger1.bitLength();
  }
  
  public static ASN1ObjectIdentifier getNamedCurveOid(String paramString) {
    if (null == paramString || paramString.length() < 1)
      return null; 
    int i = paramString.indexOf(' ');
    if (i > 0)
      paramString = paramString.substring(i + 1); 
    ASN1ObjectIdentifier aSN1ObjectIdentifier = getOID(paramString);
    if (null != aSN1ObjectIdentifier)
      return aSN1ObjectIdentifier; 
    return ECNamedCurveTable.getOID(paramString);
  }
  
  public static ASN1ObjectIdentifier getNamedCurveOid(ECParameterSpec paramECParameterSpec) {
    for (Enumeration<String> enumeration = ECNamedCurveTable.getNames(); enumeration.hasMoreElements(); ) {
      String str = enumeration.nextElement();
      X9ECParameters x9ECParameters = ECNamedCurveTable.getByName(str);
      if (x9ECParameters.getN().equals(paramECParameterSpec.getN()) && x9ECParameters
        .getH().equals(paramECParameterSpec.getH()) && x9ECParameters
        .getCurve().equals(paramECParameterSpec.getCurve()) && x9ECParameters
        .getG().equals(paramECParameterSpec.getG()))
        return ECNamedCurveTable.getOID(str); 
    } 
    return null;
  }
  
  public static X9ECParameters getNamedCurveByOid(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    X9ECParameters x9ECParameters = CustomNamedCurves.getByOID(paramASN1ObjectIdentifier);
    if (x9ECParameters == null)
      x9ECParameters = ECNamedCurveTable.getByOID(paramASN1ObjectIdentifier); 
    return x9ECParameters;
  }
  
  public static X9ECParameters getNamedCurveByName(String paramString) {
    X9ECParameters x9ECParameters = CustomNamedCurves.getByName(paramString);
    if (x9ECParameters == null)
      x9ECParameters = ECNamedCurveTable.getByName(paramString); 
    return x9ECParameters;
  }
  
  public static String getCurveName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return ECNamedCurveTable.getName(paramASN1ObjectIdentifier);
  }
  
  public static String privateKeyToString(String paramString, BigInteger paramBigInteger, ECParameterSpec paramECParameterSpec) {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    ECPoint eCPoint = (new FixedPointCombMultiplier()).multiply(paramECParameterSpec.getG(), paramBigInteger).normalize();
    stringBuffer.append(paramString);
    stringBuffer.append(" Private Key [").append(generateKeyFingerprint(eCPoint, paramECParameterSpec)).append("]").append(str);
    stringBuffer.append("            X: ").append(eCPoint.getAffineXCoord().toBigInteger().toString(16)).append(str);
    stringBuffer.append("            Y: ").append(eCPoint.getAffineYCoord().toBigInteger().toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  public static String publicKeyToString(String paramString, ECPoint paramECPoint, ECParameterSpec paramECParameterSpec) {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append(paramString);
    stringBuffer.append(" Public Key [").append(generateKeyFingerprint(paramECPoint, paramECParameterSpec)).append("]").append(str);
    stringBuffer.append("            X: ").append(paramECPoint.getAffineXCoord().toBigInteger().toString(16)).append(str);
    stringBuffer.append("            Y: ").append(paramECPoint.getAffineYCoord().toBigInteger().toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  public static String generateKeyFingerprint(ECPoint paramECPoint, ECParameterSpec paramECParameterSpec) {
    ECCurve eCCurve = paramECParameterSpec.getCurve();
    ECPoint eCPoint = paramECParameterSpec.getG();
    if (eCCurve != null)
      return (new Fingerprint(Arrays.concatenate(paramECPoint.getEncoded(false), eCCurve.getA().getEncoded(), eCCurve.getB().getEncoded(), eCPoint.getEncoded(false)))).toString(); 
    return (new Fingerprint(paramECPoint.getEncoded(false))).toString();
  }
  
  public static String getNameFrom(AlgorithmParameterSpec paramAlgorithmParameterSpec) {
    return AccessController.<String>doPrivileged((PrivilegedAction<String>)new Object(paramAlgorithmParameterSpec));
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
