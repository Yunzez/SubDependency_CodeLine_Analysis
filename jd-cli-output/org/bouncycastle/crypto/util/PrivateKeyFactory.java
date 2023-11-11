package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.oiw.ElGamalParameter;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.DHParameter;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.util.Arrays;

public class PrivateKeyFactory {
  public static AsymmetricKeyParameter createKey(byte[] paramArrayOfbyte) throws IOException {
    return createKey(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(paramArrayOfbyte)));
  }
  
  public static AsymmetricKeyParameter createKey(InputStream paramInputStream) throws IOException {
    return createKey(PrivateKeyInfo.getInstance((new ASN1InputStream(paramInputStream)).readObject()));
  }
  
  public static AsymmetricKeyParameter createKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    AlgorithmIdentifier algorithmIdentifier = paramPrivateKeyInfo.getPrivateKeyAlgorithm();
    ASN1ObjectIdentifier aSN1ObjectIdentifier = algorithmIdentifier.getAlgorithm();
    if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.rsaEncryption) || aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.id_RSASSA_PSS) || aSN1ObjectIdentifier.equals(X509ObjectIdentifiers.id_ea_rsa)) {
      RSAPrivateKey rSAPrivateKey = RSAPrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey());
      return new RSAPrivateCrtKeyParameters(rSAPrivateKey.getModulus(), rSAPrivateKey.getPublicExponent(), rSAPrivateKey.getPrivateExponent(), rSAPrivateKey.getPrime1(), rSAPrivateKey.getPrime2(), rSAPrivateKey.getExponent1(), rSAPrivateKey.getExponent2(), rSAPrivateKey.getCoefficient());
    } 
    if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.dhKeyAgreement)) {
      DHParameter dHParameter = DHParameter.getInstance(algorithmIdentifier.getParameters());
      ASN1Integer aSN1Integer = (ASN1Integer)paramPrivateKeyInfo.parsePrivateKey();
      BigInteger bigInteger = dHParameter.getL();
      boolean bool = (bigInteger == null) ? false : bigInteger.intValue();
      DHParameters dHParameters = new DHParameters(dHParameter.getP(), dHParameter.getG(), null, bool);
      return new DHPrivateKeyParameters(aSN1Integer.getValue(), dHParameters);
    } 
    if (aSN1ObjectIdentifier.equals(OIWObjectIdentifiers.elGamalAlgorithm)) {
      ElGamalParameter elGamalParameter = ElGamalParameter.getInstance(algorithmIdentifier.getParameters());
      ASN1Integer aSN1Integer = (ASN1Integer)paramPrivateKeyInfo.parsePrivateKey();
      return new ElGamalPrivateKeyParameters(aSN1Integer.getValue(), new ElGamalParameters(elGamalParameter.getP(), elGamalParameter.getG()));
    } 
    if (aSN1ObjectIdentifier.equals(X9ObjectIdentifiers.id_dsa)) {
      ASN1Integer aSN1Integer = (ASN1Integer)paramPrivateKeyInfo.parsePrivateKey();
      ASN1Encodable aSN1Encodable = algorithmIdentifier.getParameters();
      DSAParameters dSAParameters = null;
      if (aSN1Encodable != null) {
        DSAParameter dSAParameter = DSAParameter.getInstance(aSN1Encodable.toASN1Primitive());
        dSAParameters = new DSAParameters(dSAParameter.getP(), dSAParameter.getQ(), dSAParameter.getG());
      } 
      return new DSAPrivateKeyParameters(aSN1Integer.getValue(), dSAParameters);
    } 
    if (aSN1ObjectIdentifier.equals(X9ObjectIdentifiers.id_ecPublicKey)) {
      ECDomainParameters eCDomainParameters;
      X962Parameters x962Parameters = X962Parameters.getInstance(algorithmIdentifier.getParameters());
      if (x962Parameters.isNamedCurve()) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier1 = (ASN1ObjectIdentifier)x962Parameters.getParameters();
        X9ECParameters x9ECParameters = CustomNamedCurves.getByOID(aSN1ObjectIdentifier1);
        if (x9ECParameters == null)
          x9ECParameters = ECNamedCurveTable.getByOID(aSN1ObjectIdentifier1); 
        eCDomainParameters = new ECNamedDomainParameters(aSN1ObjectIdentifier1, x9ECParameters);
      } else {
        X9ECParameters x9ECParameters = X9ECParameters.getInstance(x962Parameters.getParameters());
        eCDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
      } 
      ECPrivateKey eCPrivateKey = ECPrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey());
      BigInteger bigInteger = eCPrivateKey.getKey();
      return new ECPrivateKeyParameters(bigInteger, eCDomainParameters);
    } 
    if (aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_X25519))
      return new X25519PrivateKeyParameters(getRawKey(paramPrivateKeyInfo)); 
    if (aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_X448))
      return new X448PrivateKeyParameters(getRawKey(paramPrivateKeyInfo)); 
    if (aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed25519))
      return new Ed25519PrivateKeyParameters(getRawKey(paramPrivateKeyInfo)); 
    if (aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed448))
      return new Ed448PrivateKeyParameters(getRawKey(paramPrivateKeyInfo)); 
    if (aSN1ObjectIdentifier.equals(CryptoProObjectIdentifiers.gostR3410_2001) || aSN1ObjectIdentifier.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512) || aSN1ObjectIdentifier.equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)) {
      ASN1Encodable aSN1Encodable = algorithmIdentifier.getParameters();
      GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = GOST3410PublicKeyAlgParameters.getInstance(aSN1Encodable);
      ECGOST3410Parameters eCGOST3410Parameters = null;
      BigInteger bigInteger = null;
      ASN1Primitive aSN1Primitive = aSN1Encodable.toASN1Primitive();
      if (aSN1Primitive instanceof ASN1Sequence && (ASN1Sequence.getInstance(aSN1Primitive).size() == 2 || ASN1Sequence.getInstance(aSN1Primitive).size() == 3)) {
        X9ECParameters x9ECParameters = ECGOST3410NamedCurves.getByOIDX9(gOST3410PublicKeyAlgParameters.getPublicKeyParamSet());
        eCGOST3410Parameters = new ECGOST3410Parameters(new ECNamedDomainParameters(gOST3410PublicKeyAlgParameters.getPublicKeyParamSet(), x9ECParameters), gOST3410PublicKeyAlgParameters.getPublicKeyParamSet(), gOST3410PublicKeyAlgParameters.getDigestParamSet(), gOST3410PublicKeyAlgParameters.getEncryptionParamSet());
        ASN1OctetString aSN1OctetString = paramPrivateKeyInfo.getPrivateKey();
        if ((aSN1OctetString.getOctets()).length == 32 || (aSN1OctetString.getOctets()).length == 64) {
          bigInteger = new BigInteger(1, Arrays.reverse(aSN1OctetString.getOctets()));
        } else {
          ASN1Encodable aSN1Encodable1 = paramPrivateKeyInfo.parsePrivateKey();
          if (aSN1Encodable1 instanceof ASN1Integer) {
            bigInteger = ASN1Integer.getInstance(aSN1Encodable1).getPositiveValue();
          } else {
            byte[] arrayOfByte = Arrays.reverse(ASN1OctetString.getInstance(aSN1Encodable1).getOctets());
            bigInteger = new BigInteger(1, arrayOfByte);
          } 
        } 
      } else {
        X962Parameters x962Parameters = X962Parameters.getInstance(algorithmIdentifier.getParameters());
        if (x962Parameters.isNamedCurve()) {
          ASN1ObjectIdentifier aSN1ObjectIdentifier1 = ASN1ObjectIdentifier.getInstance(x962Parameters.getParameters());
          X9ECParameters x9ECParameters = ECNamedCurveTable.getByOID(aSN1ObjectIdentifier1);
          eCGOST3410Parameters = new ECGOST3410Parameters(new ECNamedDomainParameters(aSN1ObjectIdentifier1, x9ECParameters), gOST3410PublicKeyAlgParameters.getPublicKeyParamSet(), gOST3410PublicKeyAlgParameters.getDigestParamSet(), gOST3410PublicKeyAlgParameters.getEncryptionParamSet());
        } else if (x962Parameters.isImplicitlyCA()) {
          eCGOST3410Parameters = null;
        } else {
          X9ECParameters x9ECParameters = X9ECParameters.getInstance(x962Parameters.getParameters());
          eCGOST3410Parameters = new ECGOST3410Parameters(new ECNamedDomainParameters(aSN1ObjectIdentifier, x9ECParameters), gOST3410PublicKeyAlgParameters.getPublicKeyParamSet(), gOST3410PublicKeyAlgParameters.getDigestParamSet(), gOST3410PublicKeyAlgParameters.getEncryptionParamSet());
        } 
        ASN1Encodable aSN1Encodable1 = paramPrivateKeyInfo.parsePrivateKey();
        if (aSN1Encodable1 instanceof ASN1Integer) {
          ASN1Integer aSN1Integer = ASN1Integer.getInstance(aSN1Encodable1);
          bigInteger = aSN1Integer.getValue();
        } else {
          ECPrivateKey eCPrivateKey = ECPrivateKey.getInstance(aSN1Encodable1);
          bigInteger = eCPrivateKey.getKey();
        } 
      } 
      return new ECPrivateKeyParameters(bigInteger, new ECGOST3410Parameters(eCGOST3410Parameters, gOST3410PublicKeyAlgParameters.getPublicKeyParamSet(), gOST3410PublicKeyAlgParameters.getDigestParamSet(), gOST3410PublicKeyAlgParameters.getEncryptionParamSet()));
    } 
    throw new RuntimeException("algorithm identifier in private key not recognised");
  }
  
  private static byte[] getRawKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    return ASN1OctetString.getInstance(paramPrivateKeyInfo.parsePrivateKey()).getOctets();
  }
}
