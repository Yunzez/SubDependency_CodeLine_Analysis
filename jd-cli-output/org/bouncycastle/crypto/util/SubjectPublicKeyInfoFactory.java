package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;

public class SubjectPublicKeyInfoFactory {
  private static Set cryptoProOids = new HashSet(5);
  
  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter paramAsymmetricKeyParameter) throws IOException {
    if (paramAsymmetricKeyParameter instanceof RSAKeyParameters) {
      RSAKeyParameters rSAKeyParameters = (RSAKeyParameters)paramAsymmetricKeyParameter;
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(rSAKeyParameters.getModulus(), rSAKeyParameters.getExponent()));
    } 
    if (paramAsymmetricKeyParameter instanceof DSAPublicKeyParameters) {
      DSAPublicKeyParameters dSAPublicKeyParameters = (DSAPublicKeyParameters)paramAsymmetricKeyParameter;
      DSAParameter dSAParameter = null;
      DSAParameters dSAParameters = dSAPublicKeyParameters.getParameters();
      if (dSAParameters != null)
        dSAParameter = new DSAParameter(dSAParameters.getP(), dSAParameters.getQ(), dSAParameters.getG()); 
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, dSAParameter), new ASN1Integer(dSAPublicKeyParameters.getY()));
    } 
    if (paramAsymmetricKeyParameter instanceof ECPublicKeyParameters) {
      X962Parameters x962Parameters;
      ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters)paramAsymmetricKeyParameter;
      ECDomainParameters eCDomainParameters = eCPublicKeyParameters.getParameters();
      if (eCDomainParameters == null) {
        x962Parameters = new X962Parameters(DERNull.INSTANCE);
      } else {
        if (eCDomainParameters instanceof ECGOST3410Parameters) {
          byte b1;
          byte b2;
          ASN1ObjectIdentifier aSN1ObjectIdentifier;
          ECGOST3410Parameters eCGOST3410Parameters = (ECGOST3410Parameters)eCDomainParameters;
          BigInteger bigInteger1 = eCPublicKeyParameters.getQ().getAffineXCoord().toBigInteger();
          BigInteger bigInteger2 = eCPublicKeyParameters.getQ().getAffineYCoord().toBigInteger();
          GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = new GOST3410PublicKeyAlgParameters(eCGOST3410Parameters.getPublicKeyParamSet(), eCGOST3410Parameters.getDigestParamSet());
          if (cryptoProOids.contains(eCGOST3410Parameters.getPublicKeyParamSet())) {
            b1 = 64;
            b2 = 32;
            aSN1ObjectIdentifier = CryptoProObjectIdentifiers.gostR3410_2001;
          } else {
            boolean bool = (bigInteger1.bitLength() > 256) ? true : false;
            if (bool) {
              b1 = 128;
              b2 = 64;
              aSN1ObjectIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
            } else {
              b1 = 64;
              b2 = 32;
              aSN1ObjectIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
            } 
          } 
          byte[] arrayOfByte1 = new byte[b1];
          extractBytes(arrayOfByte1, b1 / 2, 0, bigInteger1);
          extractBytes(arrayOfByte1, b1 / 2, b2, bigInteger2);
          try {
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(aSN1ObjectIdentifier, gOST3410PublicKeyAlgParameters), new DEROctetString(arrayOfByte1));
          } catch (IOException iOException) {
            return null;
          } 
        } 
        if (eCDomainParameters instanceof ECNamedDomainParameters) {
          x962Parameters = new X962Parameters(((ECNamedDomainParameters)eCDomainParameters).getName());
        } else {
          X9ECParameters x9ECParameters = new X9ECParameters(eCDomainParameters.getCurve(), new X9ECPoint(eCDomainParameters.getG(), false), eCDomainParameters.getN(), eCDomainParameters.getH(), eCDomainParameters.getSeed());
          x962Parameters = new X962Parameters(x9ECParameters);
        } 
      } 
      byte[] arrayOfByte = eCPublicKeyParameters.getQ().getEncoded(false);
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x962Parameters), arrayOfByte);
    } 
    if (paramAsymmetricKeyParameter instanceof X448PublicKeyParameters) {
      X448PublicKeyParameters x448PublicKeyParameters = (X448PublicKeyParameters)paramAsymmetricKeyParameter;
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), x448PublicKeyParameters.getEncoded());
    } 
    if (paramAsymmetricKeyParameter instanceof X25519PublicKeyParameters) {
      X25519PublicKeyParameters x25519PublicKeyParameters = (X25519PublicKeyParameters)paramAsymmetricKeyParameter;
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), x25519PublicKeyParameters.getEncoded());
    } 
    if (paramAsymmetricKeyParameter instanceof Ed448PublicKeyParameters) {
      Ed448PublicKeyParameters ed448PublicKeyParameters = (Ed448PublicKeyParameters)paramAsymmetricKeyParameter;
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), ed448PublicKeyParameters.getEncoded());
    } 
    if (paramAsymmetricKeyParameter instanceof Ed25519PublicKeyParameters) {
      Ed25519PublicKeyParameters ed25519PublicKeyParameters = (Ed25519PublicKeyParameters)paramAsymmetricKeyParameter;
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), ed25519PublicKeyParameters.getEncoded());
    } 
    throw new IOException("key parameters not recognized");
  }
  
  private static void extractBytes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, BigInteger paramBigInteger) {
    byte[] arrayOfByte = paramBigInteger.toByteArray();
    if (arrayOfByte.length < paramInt1) {
      byte[] arrayOfByte1 = new byte[paramInt1];
      System.arraycopy(arrayOfByte, 0, arrayOfByte1, arrayOfByte1.length - arrayOfByte.length, arrayOfByte.length);
      arrayOfByte = arrayOfByte1;
    } 
    for (int i = 0; i != paramInt1; i++)
      paramArrayOfbyte[paramInt2 + i] = arrayOfByte[arrayOfByte.length - 1 - i]; 
  }
  
  static {
    cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
    cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
    cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
    cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
    cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
  }
}
