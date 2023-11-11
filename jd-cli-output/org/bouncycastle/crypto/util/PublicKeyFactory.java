package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.ua.DSTU4145BinaryField;
import org.bouncycastle.asn1.ua.DSTU4145ECBinary;
import org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.ua.DSTU4145PointEncoder;
import org.bouncycastle.asn1.ua.UAObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.asn1.x9.DomainParameters;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.ValidationParams;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class PublicKeyFactory {
  private static Map converters = new HashMap<Object, Object>();
  
  public static AsymmetricKeyParameter createKey(byte[] paramArrayOfbyte) throws IOException {
    return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(paramArrayOfbyte)));
  }
  
  public static AsymmetricKeyParameter createKey(InputStream paramInputStream) throws IOException {
    return createKey(SubjectPublicKeyInfo.getInstance((new ASN1InputStream(paramInputStream)).readObject()));
  }
  
  public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    return createKey(paramSubjectPublicKeyInfo, null);
  }
  
  public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo, Object paramObject) throws IOException {
    AlgorithmIdentifier algorithmIdentifier = paramSubjectPublicKeyInfo.getAlgorithm();
    SubjectPublicKeyInfoConverter subjectPublicKeyInfoConverter = (SubjectPublicKeyInfoConverter)converters.get(algorithmIdentifier.getAlgorithm());
    if (null == subjectPublicKeyInfoConverter)
      throw new IOException("algorithm identifier in public key not recognised: " + algorithmIdentifier.getAlgorithm()); 
    return subjectPublicKeyInfoConverter.getPublicKeyParameters(paramSubjectPublicKeyInfo, paramObject);
  }
  
  private static byte[] getRawKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo, Object paramObject) {
    return paramSubjectPublicKeyInfo.getPublicKeyData().getOctets();
  }
  
  static {
    converters.put(PKCSObjectIdentifiers.rsaEncryption, new RSAConverter());
    converters.put(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSAConverter());
    converters.put(X509ObjectIdentifiers.id_ea_rsa, new RSAConverter());
    converters.put(X9ObjectIdentifiers.dhpublicnumber, new DHPublicNumberConverter());
    converters.put(PKCSObjectIdentifiers.dhKeyAgreement, new DHAgreementConverter());
    converters.put(X9ObjectIdentifiers.id_dsa, new DSAConverter());
    converters.put(OIWObjectIdentifiers.dsaWithSHA1, new DSAConverter());
    converters.put(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalConverter());
    converters.put(X9ObjectIdentifiers.id_ecPublicKey, new ECConverter());
    converters.put(CryptoProObjectIdentifiers.gostR3410_2001, new GOST3410_2001Converter());
    converters.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, new GOST3410_2012Converter());
    converters.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, new GOST3410_2012Converter());
    converters.put(UAObjectIdentifiers.dstu4145be, new DSTUConverter());
    converters.put(UAObjectIdentifiers.dstu4145le, new DSTUConverter());
    converters.put(EdECObjectIdentifiers.id_X25519, new X25519Converter());
    converters.put(EdECObjectIdentifiers.id_X448, new X448Converter());
    converters.put(EdECObjectIdentifiers.id_Ed25519, new Ed25519Converter());
    converters.put(EdECObjectIdentifiers.id_Ed448, new Ed448Converter());
  }
  
  private static class DHAgreementConverter extends SubjectPublicKeyInfoConverter {
    private DHAgreementConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      DHParameter dHParameter = DHParameter.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters());
      ASN1Integer aSN1Integer = (ASN1Integer)param1SubjectPublicKeyInfo.parsePublicKey();
      BigInteger bigInteger = dHParameter.getL();
      boolean bool = (bigInteger == null) ? false : bigInteger.intValue();
      DHParameters dHParameters = new DHParameters(dHParameter.getP(), dHParameter.getG(), null, bool);
      return new DHPublicKeyParameters(aSN1Integer.getValue(), dHParameters);
    }
  }
  
  private static class DHPublicNumberConverter extends SubjectPublicKeyInfoConverter {
    private DHPublicNumberConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      DHPublicKey dHPublicKey = DHPublicKey.getInstance(param1SubjectPublicKeyInfo.parsePublicKey());
      BigInteger bigInteger1 = dHPublicKey.getY();
      DomainParameters domainParameters = DomainParameters.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters());
      BigInteger bigInteger2 = domainParameters.getP();
      BigInteger bigInteger3 = domainParameters.getG();
      BigInteger bigInteger4 = domainParameters.getQ();
      BigInteger bigInteger5 = null;
      if (domainParameters.getJ() != null)
        bigInteger5 = domainParameters.getJ(); 
      DHValidationParameters dHValidationParameters = null;
      ValidationParams validationParams = domainParameters.getValidationParams();
      if (validationParams != null) {
        byte[] arrayOfByte = validationParams.getSeed();
        BigInteger bigInteger = validationParams.getPgenCounter();
        dHValidationParameters = new DHValidationParameters(arrayOfByte, bigInteger.intValue());
      } 
      return new DHPublicKeyParameters(bigInteger1, new DHParameters(bigInteger2, bigInteger3, bigInteger4, bigInteger5, dHValidationParameters));
    }
  }
  
  private static class DSAConverter extends SubjectPublicKeyInfoConverter {
    private DSAConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      ASN1Integer aSN1Integer = (ASN1Integer)param1SubjectPublicKeyInfo.parsePublicKey();
      ASN1Encodable aSN1Encodable = param1SubjectPublicKeyInfo.getAlgorithm().getParameters();
      DSAParameters dSAParameters = null;
      if (aSN1Encodable != null) {
        DSAParameter dSAParameter = DSAParameter.getInstance(aSN1Encodable.toASN1Primitive());
        dSAParameters = new DSAParameters(dSAParameter.getP(), dSAParameter.getQ(), dSAParameter.getG());
      } 
      return new DSAPublicKeyParameters(aSN1Integer.getValue(), dSAParameters);
    }
  }
  
  private static class DSTUConverter extends SubjectPublicKeyInfoConverter {
    private DSTUConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      ASN1OctetString aSN1OctetString;
      ECDomainParameters eCDomainParameters;
      AlgorithmIdentifier algorithmIdentifier = param1SubjectPublicKeyInfo.getAlgorithm();
      ASN1ObjectIdentifier aSN1ObjectIdentifier = algorithmIdentifier.getAlgorithm();
      DSTU4145Params dSTU4145Params = DSTU4145Params.getInstance(algorithmIdentifier.getParameters());
      try {
        aSN1OctetString = (ASN1OctetString)param1SubjectPublicKeyInfo.parsePublicKey();
      } catch (IOException iOException) {
        throw new IllegalArgumentException("error recovering DSTU public key");
      } 
      byte[] arrayOfByte = Arrays.clone(aSN1OctetString.getOctets());
      if (aSN1ObjectIdentifier.equals(UAObjectIdentifiers.dstu4145le))
        reverseBytes(arrayOfByte); 
      if (dSTU4145Params.isNamedCurve()) {
        eCDomainParameters = DSTU4145NamedCurves.getByOID(dSTU4145Params.getNamedCurve());
      } else {
        DSTU4145ECBinary dSTU4145ECBinary = dSTU4145Params.getECBinary();
        byte[] arrayOfByte1 = dSTU4145ECBinary.getB();
        if (aSN1ObjectIdentifier.equals(UAObjectIdentifiers.dstu4145le))
          reverseBytes(arrayOfByte1); 
        BigInteger bigInteger = new BigInteger(1, arrayOfByte1);
        DSTU4145BinaryField dSTU4145BinaryField = dSTU4145ECBinary.getField();
        ECCurve.F2m f2m = new ECCurve.F2m(dSTU4145BinaryField.getM(), dSTU4145BinaryField.getK1(), dSTU4145BinaryField.getK2(), dSTU4145BinaryField.getK3(), dSTU4145ECBinary.getA(), bigInteger);
        byte[] arrayOfByte2 = dSTU4145ECBinary.getG();
        if (aSN1ObjectIdentifier.equals(UAObjectIdentifiers.dstu4145le))
          reverseBytes(arrayOfByte2); 
        ECPoint eCPoint1 = DSTU4145PointEncoder.decodePoint(f2m, arrayOfByte2);
        eCDomainParameters = new ECDomainParameters(f2m, eCPoint1, dSTU4145ECBinary.getN());
      } 
      ECPoint eCPoint = DSTU4145PointEncoder.decodePoint(eCDomainParameters.getCurve(), arrayOfByte);
      return new ECPublicKeyParameters(eCPoint, eCDomainParameters);
    }
    
    private void reverseBytes(byte[] param1ArrayOfbyte) {
      for (byte b = 0; b < param1ArrayOfbyte.length / 2; b++) {
        byte b1 = param1ArrayOfbyte[b];
        param1ArrayOfbyte[b] = param1ArrayOfbyte[param1ArrayOfbyte.length - 1 - b];
        param1ArrayOfbyte[param1ArrayOfbyte.length - 1 - b] = b1;
      } 
    }
  }
  
  private static class ECConverter extends SubjectPublicKeyInfoConverter {
    private ECConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      ECDomainParameters eCDomainParameters;
      X962Parameters x962Parameters = X962Parameters.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters());
      if (x962Parameters.isNamedCurve()) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier)x962Parameters.getParameters();
        X9ECParameters x9ECParameters = CustomNamedCurves.getByOID(aSN1ObjectIdentifier);
        if (x9ECParameters == null)
          x9ECParameters = ECNamedCurveTable.getByOID(aSN1ObjectIdentifier); 
        eCDomainParameters = new ECNamedDomainParameters(aSN1ObjectIdentifier, x9ECParameters);
      } else if (x962Parameters.isImplicitlyCA()) {
        eCDomainParameters = (ECDomainParameters)param1Object;
      } else {
        X9ECParameters x9ECParameters = X9ECParameters.getInstance(x962Parameters.getParameters());
        eCDomainParameters = new ECDomainParameters(x9ECParameters);
      } 
      ASN1BitString aSN1BitString = param1SubjectPublicKeyInfo.getPublicKeyData();
      byte[] arrayOfByte = aSN1BitString.getBytes();
      ASN1OctetString aSN1OctetString = new DEROctetString(arrayOfByte);
      if (arrayOfByte[0] == 4 && arrayOfByte[1] == arrayOfByte.length - 2 && (arrayOfByte[2] == 2 || arrayOfByte[2] == 3)) {
        int i = (new X9IntegerConverter()).getByteLength(eCDomainParameters.getCurve());
        if (i >= arrayOfByte.length - 3)
          try {
            aSN1OctetString = (ASN1OctetString)ASN1Primitive.fromByteArray(arrayOfByte);
          } catch (IOException iOException) {
            throw new IllegalArgumentException("error recovering public key");
          }  
      } 
      X9ECPoint x9ECPoint = new X9ECPoint(eCDomainParameters.getCurve(), aSN1OctetString);
      return new ECPublicKeyParameters(x9ECPoint.getPoint(), eCDomainParameters);
    }
  }
  
  private static class Ed25519Converter extends SubjectPublicKeyInfoConverter {
    private Ed25519Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      return new Ed25519PublicKeyParameters(PublicKeyFactory.getRawKey(param1SubjectPublicKeyInfo, param1Object));
    }
  }
  
  private static class Ed448Converter extends SubjectPublicKeyInfoConverter {
    private Ed448Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      return new Ed448PublicKeyParameters(PublicKeyFactory.getRawKey(param1SubjectPublicKeyInfo, param1Object));
    }
  }
  
  private static class ElGamalConverter extends SubjectPublicKeyInfoConverter {
    private ElGamalConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      ElGamalParameter elGamalParameter = ElGamalParameter.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters());
      ASN1Integer aSN1Integer = (ASN1Integer)param1SubjectPublicKeyInfo.parsePublicKey();
      return new ElGamalPublicKeyParameters(aSN1Integer.getValue(), new ElGamalParameters(elGamalParameter.getP(), elGamalParameter.getG()));
    }
  }
  
  private static class GOST3410_2001Converter extends SubjectPublicKeyInfoConverter {
    private GOST3410_2001Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      ASN1OctetString aSN1OctetString;
      AlgorithmIdentifier algorithmIdentifier = param1SubjectPublicKeyInfo.getAlgorithm();
      GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = GOST3410PublicKeyAlgParameters.getInstance(algorithmIdentifier.getParameters());
      ASN1ObjectIdentifier aSN1ObjectIdentifier = gOST3410PublicKeyAlgParameters.getPublicKeyParamSet();
      ECGOST3410Parameters eCGOST3410Parameters = new ECGOST3410Parameters(new ECNamedDomainParameters(aSN1ObjectIdentifier, ECGOST3410NamedCurves.getByOIDX9(aSN1ObjectIdentifier)), aSN1ObjectIdentifier, gOST3410PublicKeyAlgParameters.getDigestParamSet(), gOST3410PublicKeyAlgParameters.getEncryptionParamSet());
      try {
        aSN1OctetString = (ASN1OctetString)param1SubjectPublicKeyInfo.parsePublicKey();
      } catch (IOException iOException) {
        throw new IllegalArgumentException("error recovering GOST3410_2001 public key");
      } 
      byte b1 = 32;
      int i = 2 * b1;
      byte[] arrayOfByte1 = aSN1OctetString.getOctets();
      if (arrayOfByte1.length != i)
        throw new IllegalArgumentException("invalid length for GOST3410_2001 public key"); 
      byte[] arrayOfByte2 = new byte[1 + i];
      arrayOfByte2[0] = 4;
      for (byte b2 = 1; b2 <= b1; b2++) {
        arrayOfByte2[b2] = arrayOfByte1[b1 - b2];
        arrayOfByte2[b2 + b1] = arrayOfByte1[i - b2];
      } 
      ECPoint eCPoint = eCGOST3410Parameters.getCurve().decodePoint(arrayOfByte2);
      return new ECPublicKeyParameters(eCPoint, eCGOST3410Parameters);
    }
  }
  
  private static class GOST3410_2012Converter extends SubjectPublicKeyInfoConverter {
    private GOST3410_2012Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      ASN1OctetString aSN1OctetString;
      AlgorithmIdentifier algorithmIdentifier = param1SubjectPublicKeyInfo.getAlgorithm();
      ASN1ObjectIdentifier aSN1ObjectIdentifier1 = algorithmIdentifier.getAlgorithm();
      GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = GOST3410PublicKeyAlgParameters.getInstance(algorithmIdentifier.getParameters());
      ASN1ObjectIdentifier aSN1ObjectIdentifier2 = gOST3410PublicKeyAlgParameters.getPublicKeyParamSet();
      ECGOST3410Parameters eCGOST3410Parameters = new ECGOST3410Parameters(new ECNamedDomainParameters(aSN1ObjectIdentifier2, ECGOST3410NamedCurves.getByOIDX9(aSN1ObjectIdentifier2)), aSN1ObjectIdentifier2, gOST3410PublicKeyAlgParameters.getDigestParamSet(), gOST3410PublicKeyAlgParameters.getEncryptionParamSet());
      try {
        aSN1OctetString = (ASN1OctetString)param1SubjectPublicKeyInfo.parsePublicKey();
      } catch (IOException iOException) {
        throw new IllegalArgumentException("error recovering GOST3410_2012 public key");
      } 
      byte b1 = 32;
      if (aSN1ObjectIdentifier1.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512))
        b1 = 64; 
      int i = 2 * b1;
      byte[] arrayOfByte1 = aSN1OctetString.getOctets();
      if (arrayOfByte1.length != i)
        throw new IllegalArgumentException("invalid length for GOST3410_2012 public key"); 
      byte[] arrayOfByte2 = new byte[1 + i];
      arrayOfByte2[0] = 4;
      for (byte b2 = 1; b2 <= b1; b2++) {
        arrayOfByte2[b2] = arrayOfByte1[b1 - b2];
        arrayOfByte2[b2 + b1] = arrayOfByte1[i - b2];
      } 
      ECPoint eCPoint = eCGOST3410Parameters.getCurve().decodePoint(arrayOfByte2);
      return new ECPublicKeyParameters(eCPoint, eCGOST3410Parameters);
    }
  }
  
  private static class RSAConverter extends SubjectPublicKeyInfoConverter {
    private RSAConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      RSAPublicKey rSAPublicKey = RSAPublicKey.getInstance(param1SubjectPublicKeyInfo.parsePublicKey());
      return new RSAKeyParameters(false, rSAPublicKey.getModulus(), rSAPublicKey.getPublicExponent());
    }
  }
  
  private static abstract class SubjectPublicKeyInfoConverter {
    private SubjectPublicKeyInfoConverter() {}
    
    abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException;
  }
  
  private static class X25519Converter extends SubjectPublicKeyInfoConverter {
    private X25519Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      return new X25519PublicKeyParameters(PublicKeyFactory.getRawKey(param1SubjectPublicKeyInfo, param1Object));
    }
  }
  
  private static class X448Converter extends SubjectPublicKeyInfoConverter {
    private X448Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) {
      return new X448PublicKeyParameters(PublicKeyFactory.getRawKey(param1SubjectPublicKeyInfo, param1Object));
    }
  }
}
