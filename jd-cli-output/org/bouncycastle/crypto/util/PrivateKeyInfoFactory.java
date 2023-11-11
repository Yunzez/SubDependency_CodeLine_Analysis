package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class PrivateKeyInfoFactory {
  private static Set cryptoProOids = new HashSet(5);
  
  public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter paramAsymmetricKeyParameter) throws IOException {
    return createPrivateKeyInfo(paramAsymmetricKeyParameter, null);
  }
  
  public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter paramAsymmetricKeyParameter, ASN1Set paramASN1Set) throws IOException {
    if (paramAsymmetricKeyParameter instanceof org.bouncycastle.crypto.params.RSAKeyParameters) {
      RSAPrivateCrtKeyParameters rSAPrivateCrtKeyParameters = (RSAPrivateCrtKeyParameters)paramAsymmetricKeyParameter;
      return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKey(rSAPrivateCrtKeyParameters.getModulus(), rSAPrivateCrtKeyParameters.getPublicExponent(), rSAPrivateCrtKeyParameters.getExponent(), rSAPrivateCrtKeyParameters.getP(), rSAPrivateCrtKeyParameters.getQ(), rSAPrivateCrtKeyParameters.getDP(), rSAPrivateCrtKeyParameters.getDQ(), rSAPrivateCrtKeyParameters.getQInv()), paramASN1Set);
    } 
    if (paramAsymmetricKeyParameter instanceof DSAPrivateKeyParameters) {
      DSAPrivateKeyParameters dSAPrivateKeyParameters = (DSAPrivateKeyParameters)paramAsymmetricKeyParameter;
      DSAParameters dSAParameters = dSAPrivateKeyParameters.getParameters();
      return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(dSAParameters.getP(), dSAParameters.getQ(), dSAParameters.getG())), new ASN1Integer(dSAPrivateKeyParameters.getX()), paramASN1Set);
    } 
    if (paramAsymmetricKeyParameter instanceof ECPrivateKeyParameters) {
      X962Parameters x962Parameters;
      int i;
      ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)paramAsymmetricKeyParameter;
      ECDomainParameters eCDomainParameters = eCPrivateKeyParameters.getParameters();
      if (eCDomainParameters == null) {
        x962Parameters = new X962Parameters(DERNull.INSTANCE);
        i = eCPrivateKeyParameters.getD().bitLength();
      } else {
        if (eCDomainParameters instanceof ECGOST3410Parameters) {
          byte b;
          ASN1ObjectIdentifier aSN1ObjectIdentifier;
          GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = new GOST3410PublicKeyAlgParameters(((ECGOST3410Parameters)eCDomainParameters).getPublicKeyParamSet(), ((ECGOST3410Parameters)eCDomainParameters).getDigestParamSet(), ((ECGOST3410Parameters)eCDomainParameters).getEncryptionParamSet());
          if (cryptoProOids.contains(gOST3410PublicKeyAlgParameters.getPublicKeyParamSet())) {
            b = 32;
            aSN1ObjectIdentifier = CryptoProObjectIdentifiers.gostR3410_2001;
          } else {
            boolean bool = (eCPrivateKeyParameters.getD().bitLength() > 256) ? true : false;
            aSN1ObjectIdentifier = bool ? RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512 : RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
            b = bool ? 64 : 32;
          } 
          byte[] arrayOfByte = new byte[b];
          extractBytes(arrayOfByte, b, 0, eCPrivateKeyParameters.getD());
          return new PrivateKeyInfo(new AlgorithmIdentifier(aSN1ObjectIdentifier, gOST3410PublicKeyAlgParameters), new DEROctetString(arrayOfByte));
        } 
        if (eCDomainParameters instanceof ECNamedDomainParameters) {
          x962Parameters = new X962Parameters(((ECNamedDomainParameters)eCDomainParameters).getName());
          i = eCDomainParameters.getN().bitLength();
        } else {
          X9ECParameters x9ECParameters = new X9ECParameters(eCDomainParameters.getCurve(), new X9ECPoint(eCDomainParameters.getG(), false), eCDomainParameters.getN(), eCDomainParameters.getH(), eCDomainParameters.getSeed());
          x962Parameters = new X962Parameters(x9ECParameters);
          i = eCDomainParameters.getN().bitLength();
        } 
      } 
      ECPoint eCPoint = (new FixedPointCombMultiplier()).multiply(eCDomainParameters.getG(), eCPrivateKeyParameters.getD());
      DERBitString dERBitString = new DERBitString(eCPoint.getEncoded(false));
      return new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, x962Parameters), new ECPrivateKey(i, eCPrivateKeyParameters.getD(), dERBitString, x962Parameters), paramASN1Set);
    } 
    if (paramAsymmetricKeyParameter instanceof X448PrivateKeyParameters) {
      X448PrivateKeyParameters x448PrivateKeyParameters = (X448PrivateKeyParameters)paramAsymmetricKeyParameter;
      return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), new DEROctetString(x448PrivateKeyParameters.getEncoded()), paramASN1Set, x448PrivateKeyParameters.generatePublicKey().getEncoded());
    } 
    if (paramAsymmetricKeyParameter instanceof X25519PrivateKeyParameters) {
      X25519PrivateKeyParameters x25519PrivateKeyParameters = (X25519PrivateKeyParameters)paramAsymmetricKeyParameter;
      return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), new DEROctetString(x25519PrivateKeyParameters.getEncoded()), paramASN1Set, x25519PrivateKeyParameters.generatePublicKey().getEncoded());
    } 
    if (paramAsymmetricKeyParameter instanceof Ed448PrivateKeyParameters) {
      Ed448PrivateKeyParameters ed448PrivateKeyParameters = (Ed448PrivateKeyParameters)paramAsymmetricKeyParameter;
      return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), new DEROctetString(ed448PrivateKeyParameters.getEncoded()), paramASN1Set, ed448PrivateKeyParameters.generatePublicKey().getEncoded());
    } 
    if (paramAsymmetricKeyParameter instanceof Ed25519PrivateKeyParameters) {
      Ed25519PrivateKeyParameters ed25519PrivateKeyParameters = (Ed25519PrivateKeyParameters)paramAsymmetricKeyParameter;
      return new PrivateKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(ed25519PrivateKeyParameters.getEncoded()), paramASN1Set, ed25519PrivateKeyParameters.generatePublicKey().getEncoded());
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
