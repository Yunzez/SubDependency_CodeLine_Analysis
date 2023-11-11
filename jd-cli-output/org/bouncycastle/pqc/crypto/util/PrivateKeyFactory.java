package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTPrivateKey;
import org.bouncycastle.pqc.asn1.XMSSPrivateKey;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.BDS;
import org.bouncycastle.pqc.crypto.xmss.BDSStateMap;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

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
    if (aSN1ObjectIdentifier.on(BCObjectIdentifiers.qTESLA)) {
      ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(paramPrivateKeyInfo.parsePrivateKey());
      return new QTESLAPrivateKeyParameters(Utils.qTeslaLookupSecurityCategory(paramPrivateKeyInfo.getPrivateKeyAlgorithm()), aSN1OctetString.getOctets());
    } 
    if (aSN1ObjectIdentifier.equals(BCObjectIdentifiers.sphincs256))
      return new SPHINCSPrivateKeyParameters(ASN1OctetString.getInstance(paramPrivateKeyInfo.parsePrivateKey()).getOctets(), Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(paramPrivateKeyInfo.getPrivateKeyAlgorithm().getParameters()))); 
    if (aSN1ObjectIdentifier.equals(BCObjectIdentifiers.newHope))
      return new NHPrivateKeyParameters(convert(ASN1OctetString.getInstance(paramPrivateKeyInfo.parsePrivateKey()).getOctets())); 
    if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig)) {
      byte[] arrayOfByte = ASN1OctetString.getInstance(paramPrivateKeyInfo.parsePrivateKey()).getOctets();
      ASN1BitString aSN1BitString = paramPrivateKeyInfo.getPublicKeyData();
      if (Pack.bigEndianToInt(arrayOfByte, 0) == 1) {
        if (aSN1BitString != null) {
          byte[] arrayOfByte1 = aSN1BitString.getOctets();
          return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(arrayOfByte, 4, arrayOfByte.length), Arrays.copyOfRange(arrayOfByte1, 4, arrayOfByte1.length));
        } 
        return LMSPrivateKeyParameters.getInstance(Arrays.copyOfRange(arrayOfByte, 4, arrayOfByte.length));
      } 
      if (aSN1BitString != null) {
        byte[] arrayOfByte1 = aSN1BitString.getOctets();
        return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(arrayOfByte, 4, arrayOfByte.length), arrayOfByte1);
      } 
      return HSSPrivateKeyParameters.getInstance(Arrays.copyOfRange(arrayOfByte, 4, arrayOfByte.length));
    } 
    if (aSN1ObjectIdentifier.equals(BCObjectIdentifiers.xmss)) {
      XMSSKeyParams xMSSKeyParams = XMSSKeyParams.getInstance(paramPrivateKeyInfo.getPrivateKeyAlgorithm().getParameters());
      ASN1ObjectIdentifier aSN1ObjectIdentifier1 = xMSSKeyParams.getTreeDigest().getAlgorithm();
      XMSSPrivateKey xMSSPrivateKey = XMSSPrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey());
      try {
        XMSSPrivateKeyParameters.Builder builder = (new XMSSPrivateKeyParameters.Builder(new XMSSParameters(xMSSKeyParams.getHeight(), Utils.getDigest(aSN1ObjectIdentifier1)))).withIndex(xMSSPrivateKey.getIndex()).withSecretKeySeed(xMSSPrivateKey.getSecretKeySeed()).withSecretKeyPRF(xMSSPrivateKey.getSecretKeyPRF()).withPublicSeed(xMSSPrivateKey.getPublicSeed()).withRoot(xMSSPrivateKey.getRoot());
        if (xMSSPrivateKey.getVersion() != 0)
          builder.withMaxIndex(xMSSPrivateKey.getMaxIndex()); 
        if (xMSSPrivateKey.getBdsState() != null) {
          BDS bDS = (BDS)XMSSUtil.deserialize(xMSSPrivateKey.getBdsState(), BDS.class);
          builder.withBDSState(bDS.withWOTSDigest(aSN1ObjectIdentifier1));
        } 
        return builder.build();
      } catch (ClassNotFoundException classNotFoundException) {
        throw new IOException("ClassNotFoundException processing BDS state: " + classNotFoundException.getMessage());
      } 
    } 
    if (aSN1ObjectIdentifier.equals(PQCObjectIdentifiers.xmss_mt)) {
      XMSSMTKeyParams xMSSMTKeyParams = XMSSMTKeyParams.getInstance(paramPrivateKeyInfo.getPrivateKeyAlgorithm().getParameters());
      ASN1ObjectIdentifier aSN1ObjectIdentifier1 = xMSSMTKeyParams.getTreeDigest().getAlgorithm();
      try {
        XMSSMTPrivateKey xMSSMTPrivateKey = XMSSMTPrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey());
        XMSSMTPrivateKeyParameters.Builder builder = (new XMSSMTPrivateKeyParameters.Builder(new XMSSMTParameters(xMSSMTKeyParams.getHeight(), xMSSMTKeyParams.getLayers(), Utils.getDigest(aSN1ObjectIdentifier1)))).withIndex(xMSSMTPrivateKey.getIndex()).withSecretKeySeed(xMSSMTPrivateKey.getSecretKeySeed()).withSecretKeyPRF(xMSSMTPrivateKey.getSecretKeyPRF()).withPublicSeed(xMSSMTPrivateKey.getPublicSeed()).withRoot(xMSSMTPrivateKey.getRoot());
        if (xMSSMTPrivateKey.getVersion() != 0)
          builder.withMaxIndex(xMSSMTPrivateKey.getMaxIndex()); 
        if (xMSSMTPrivateKey.getBdsState() != null) {
          BDSStateMap bDSStateMap = (BDSStateMap)XMSSUtil.deserialize(xMSSMTPrivateKey.getBdsState(), BDSStateMap.class);
          builder.withBDSState(bDSStateMap.withWOTSDigest(aSN1ObjectIdentifier1));
        } 
        return builder.build();
      } catch (ClassNotFoundException classNotFoundException) {
        throw new IOException("ClassNotFoundException processing BDS state: " + classNotFoundException.getMessage());
      } 
    } 
    if (aSN1ObjectIdentifier.equals(PQCObjectIdentifiers.mcElieceCca2)) {
      McElieceCCA2PrivateKey mcElieceCCA2PrivateKey = McElieceCCA2PrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey());
      return new McElieceCCA2PrivateKeyParameters(mcElieceCCA2PrivateKey.getN(), mcElieceCCA2PrivateKey.getK(), mcElieceCCA2PrivateKey.getField(), mcElieceCCA2PrivateKey.getGoppaPoly(), mcElieceCCA2PrivateKey.getP(), Utils.getDigestName(mcElieceCCA2PrivateKey.getDigest().getAlgorithm()));
    } 
    throw new RuntimeException("algorithm identifier in private key not recognised");
  }
  
  private static short[] convert(byte[] paramArrayOfbyte) {
    short[] arrayOfShort = new short[paramArrayOfbyte.length / 2];
    for (byte b = 0; b != arrayOfShort.length; b++)
      arrayOfShort[b] = Pack.littleEndianToShort(paramArrayOfbyte, b * 2); 
    return arrayOfShort;
  }
}
