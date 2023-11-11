package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTPublicKey;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.lms.Composer;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;

public class SubjectPublicKeyInfoFactory {
  public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter paramAsymmetricKeyParameter) throws IOException {
    if (paramAsymmetricKeyParameter instanceof QTESLAPublicKeyParameters) {
      QTESLAPublicKeyParameters qTESLAPublicKeyParameters = (QTESLAPublicKeyParameters)paramAsymmetricKeyParameter;
      AlgorithmIdentifier algorithmIdentifier = Utils.qTeslaLookupAlgID(qTESLAPublicKeyParameters.getSecurityCategory());
      return new SubjectPublicKeyInfo(algorithmIdentifier, qTESLAPublicKeyParameters.getPublicData());
    } 
    if (paramAsymmetricKeyParameter instanceof SPHINCSPublicKeyParameters) {
      SPHINCSPublicKeyParameters sPHINCSPublicKeyParameters = (SPHINCSPublicKeyParameters)paramAsymmetricKeyParameter;
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(Utils.sphincs256LookupTreeAlgID(sPHINCSPublicKeyParameters.getTreeDigest())));
      return new SubjectPublicKeyInfo(algorithmIdentifier, sPHINCSPublicKeyParameters.getKeyData());
    } 
    if (paramAsymmetricKeyParameter instanceof NHPublicKeyParameters) {
      NHPublicKeyParameters nHPublicKeyParameters = (NHPublicKeyParameters)paramAsymmetricKeyParameter;
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
      return new SubjectPublicKeyInfo(algorithmIdentifier, nHPublicKeyParameters.getPubData());
    } 
    if (paramAsymmetricKeyParameter instanceof LMSPublicKeyParameters) {
      LMSPublicKeyParameters lMSPublicKeyParameters = (LMSPublicKeyParameters)paramAsymmetricKeyParameter;
      byte[] arrayOfByte = Composer.compose().u32str(1).bytes(lMSPublicKeyParameters).build();
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
      return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(arrayOfByte));
    } 
    if (paramAsymmetricKeyParameter instanceof HSSPublicKeyParameters) {
      HSSPublicKeyParameters hSSPublicKeyParameters = (HSSPublicKeyParameters)paramAsymmetricKeyParameter;
      byte[] arrayOfByte = Composer.compose().u32str(hSSPublicKeyParameters.getL()).bytes(hSSPublicKeyParameters.getLMSPublicKey()).build();
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
      return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(arrayOfByte));
    } 
    if (paramAsymmetricKeyParameter instanceof XMSSPublicKeyParameters) {
      XMSSPublicKeyParameters xMSSPublicKeyParameters = (XMSSPublicKeyParameters)paramAsymmetricKeyParameter;
      byte[] arrayOfByte1 = xMSSPublicKeyParameters.getPublicSeed();
      byte[] arrayOfByte2 = xMSSPublicKeyParameters.getRoot();
      byte[] arrayOfByte3 = xMSSPublicKeyParameters.getEncoded();
      if (arrayOfByte3.length > arrayOfByte1.length + arrayOfByte2.length) {
        AlgorithmIdentifier algorithmIdentifier1 = new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmss);
        return new SubjectPublicKeyInfo(algorithmIdentifier1, new DEROctetString(arrayOfByte3));
      } 
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss, new XMSSKeyParams(xMSSPublicKeyParameters.getParameters().getHeight(), Utils.xmssLookupTreeAlgID(xMSSPublicKeyParameters.getTreeDigest())));
      return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSPublicKey(arrayOfByte1, arrayOfByte2));
    } 
    if (paramAsymmetricKeyParameter instanceof XMSSMTPublicKeyParameters) {
      XMSSMTPublicKeyParameters xMSSMTPublicKeyParameters = (XMSSMTPublicKeyParameters)paramAsymmetricKeyParameter;
      byte[] arrayOfByte1 = xMSSMTPublicKeyParameters.getPublicSeed();
      byte[] arrayOfByte2 = xMSSMTPublicKeyParameters.getRoot();
      byte[] arrayOfByte3 = xMSSMTPublicKeyParameters.getEncoded();
      if (arrayOfByte3.length > arrayOfByte1.length + arrayOfByte2.length) {
        AlgorithmIdentifier algorithmIdentifier1 = new AlgorithmIdentifier(IsaraObjectIdentifiers.id_alg_xmssmt);
        return new SubjectPublicKeyInfo(algorithmIdentifier1, new DEROctetString(arrayOfByte3));
      } 
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyParams(xMSSMTPublicKeyParameters.getParameters().getHeight(), xMSSMTPublicKeyParameters.getParameters().getLayers(), Utils.xmssLookupTreeAlgID(xMSSMTPublicKeyParameters.getTreeDigest())));
      return new SubjectPublicKeyInfo(algorithmIdentifier, new XMSSMTPublicKey(xMSSMTPublicKeyParameters.getPublicSeed(), xMSSMTPublicKeyParameters.getRoot()));
    } 
    if (paramAsymmetricKeyParameter instanceof McElieceCCA2PublicKeyParameters) {
      McElieceCCA2PublicKeyParameters mcElieceCCA2PublicKeyParameters = (McElieceCCA2PublicKeyParameters)paramAsymmetricKeyParameter;
      McElieceCCA2PublicKey mcElieceCCA2PublicKey = new McElieceCCA2PublicKey(mcElieceCCA2PublicKeyParameters.getN(), mcElieceCCA2PublicKeyParameters.getT(), mcElieceCCA2PublicKeyParameters.getG(), Utils.getAlgorithmIdentifier(mcElieceCCA2PublicKeyParameters.getDigest()));
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);
      return new SubjectPublicKeyInfo(algorithmIdentifier, mcElieceCCA2PublicKey);
    } 
    throw new IOException("key parameters not recognized");
  }
}
