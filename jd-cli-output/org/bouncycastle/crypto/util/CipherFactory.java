package org.bouncycastle.crypto.util;

import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.CAST5CBCParameters;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RC2CBCParameter;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RC2Parameters;
import org.bouncycastle.internal.asn1.cms.CCMParameters;
import org.bouncycastle.internal.asn1.cms.GCMParameters;

public class CipherFactory {
  private static final short[] rc2Ekb = new short[] { 
      93, 190, 155, 139, 17, 153, 110, 77, 89, 243, 
      133, 166, 63, 183, 131, 197, 228, 115, 107, 58, 
      104, 90, 192, 71, 160, 100, 52, 12, 241, 208, 
      82, 165, 185, 30, 150, 67, 65, 216, 212, 44, 
      219, 248, 7, 119, 42, 202, 235, 239, 16, 28, 
      22, 13, 56, 114, 47, 137, 193, 249, 128, 196, 
      109, 174, 48, 61, 206, 32, 99, 254, 230, 26, 
      199, 184, 80, 232, 36, 23, 252, 37, 111, 187, 
      106, 163, 68, 83, 217, 162, 1, 171, 188, 182, 
      31, 152, 238, 154, 167, 45, 79, 158, 142, 172, 
      224, 198, 73, 70, 41, 244, 148, 138, 175, 225, 
      91, 195, 179, 123, 87, 209, 124, 156, 237, 135, 
      64, 140, 226, 203, 147, 20, 201, 97, 46, 229, 
      204, 246, 94, 168, 92, 214, 117, 141, 98, 149, 
      88, 105, 118, 161, 74, 181, 85, 9, 120, 51, 
      130, 215, 221, 121, 245, 27, 11, 222, 38, 33, 
      40, 116, 4, 151, 86, 223, 60, 240, 55, 57, 
      220, 255, 6, 164, 234, 66, 8, 218, 180, 113, 
      176, 207, 18, 122, 78, 250, 108, 29, 132, 0, 
      200, 127, 145, 69, 170, 43, 194, 177, 143, 213, 
      186, 242, 173, 25, 178, 103, 54, 247, 15, 10, 
      146, 125, 227, 157, 233, 144, 62, 35, 39, 102, 
      19, 236, 129, 21, 189, 34, 191, 159, 126, 169, 
      81, 75, 76, 251, 2, 211, 112, 134, 49, 231, 
      59, 5, 3, 84, 96, 72, 101, 24, 210, 205, 
      95, 50, 136, 14, 53, 253 };
  
  public static Object createContentCipher(boolean paramBoolean, CipherParameters paramCipherParameters, AlgorithmIdentifier paramAlgorithmIdentifier) throws IllegalArgumentException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramAlgorithmIdentifier.getAlgorithm();
    if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.rc4)) {
      RC4Engine rC4Engine = new RC4Engine();
      rC4Engine.init(paramBoolean, paramCipherParameters);
      return rC4Engine;
    } 
    if (aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes128_GCM) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes192_GCM) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes256_GCM)) {
      AEADBlockCipher aEADBlockCipher = createAEADCipher(paramAlgorithmIdentifier.getAlgorithm());
      GCMParameters gCMParameters = GCMParameters.getInstance(paramAlgorithmIdentifier.getParameters());
      if (!(paramCipherParameters instanceof KeyParameter))
        throw new IllegalArgumentException("key data must be accessible for GCM operation"); 
      AEADParameters aEADParameters = new AEADParameters((KeyParameter)paramCipherParameters, gCMParameters.getIcvLen() * 8, gCMParameters.getNonce());
      aEADBlockCipher.init(paramBoolean, aEADParameters);
      return aEADBlockCipher;
    } 
    if (aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes128_CCM) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes192_CCM) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes256_CCM)) {
      AEADBlockCipher aEADBlockCipher = createAEADCipher(paramAlgorithmIdentifier.getAlgorithm());
      CCMParameters cCMParameters = CCMParameters.getInstance(paramAlgorithmIdentifier.getParameters());
      if (!(paramCipherParameters instanceof KeyParameter))
        throw new IllegalArgumentException("key data must be accessible for GCM operation"); 
      AEADParameters aEADParameters = new AEADParameters((KeyParameter)paramCipherParameters, cCMParameters.getIcvLen() * 8, cCMParameters.getNonce());
      aEADBlockCipher.init(paramBoolean, aEADParameters);
      return aEADBlockCipher;
    } 
    BufferedBlockCipher bufferedBlockCipher = createCipher(paramAlgorithmIdentifier.getAlgorithm());
    ASN1Primitive aSN1Primitive = paramAlgorithmIdentifier.getParameters().toASN1Primitive();
    if (aSN1Primitive != null && !(aSN1Primitive instanceof org.bouncycastle.asn1.ASN1Null)) {
      if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.des_EDE3_CBC) || aSN1ObjectIdentifier.equals(AlgorithmIdentifierFactory.IDEA_CBC) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes128_CBC) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes192_CBC) || aSN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_aes256_CBC) || aSN1ObjectIdentifier.equals(NTTObjectIdentifiers.id_camellia128_cbc) || aSN1ObjectIdentifier.equals(NTTObjectIdentifiers.id_camellia192_cbc) || aSN1ObjectIdentifier.equals(NTTObjectIdentifiers.id_camellia256_cbc) || aSN1ObjectIdentifier.equals(KISAObjectIdentifiers.id_seedCBC) || aSN1ObjectIdentifier.equals(OIWObjectIdentifiers.desCBC)) {
        bufferedBlockCipher.init(paramBoolean, new ParametersWithIV(paramCipherParameters, ASN1OctetString.getInstance(aSN1Primitive).getOctets()));
      } else if (aSN1ObjectIdentifier.equals(AlgorithmIdentifierFactory.CAST5_CBC)) {
        CAST5CBCParameters cAST5CBCParameters = CAST5CBCParameters.getInstance(aSN1Primitive);
        bufferedBlockCipher.init(paramBoolean, new ParametersWithIV(paramCipherParameters, cAST5CBCParameters.getIV()));
      } else if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.RC2_CBC)) {
        RC2CBCParameter rC2CBCParameter = RC2CBCParameter.getInstance(aSN1Primitive);
        bufferedBlockCipher.init(paramBoolean, new ParametersWithIV(new RC2Parameters(((KeyParameter)paramCipherParameters).getKey(), rc2Ekb[rC2CBCParameter.getRC2ParameterVersion().intValue()]), rC2CBCParameter.getIV()));
      } else {
        throw new IllegalArgumentException("cannot match parameters");
      } 
    } else if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.des_EDE3_CBC) || aSN1ObjectIdentifier.equals(AlgorithmIdentifierFactory.IDEA_CBC) || aSN1ObjectIdentifier.equals(AlgorithmIdentifierFactory.CAST5_CBC)) {
      bufferedBlockCipher.init(paramBoolean, new ParametersWithIV(paramCipherParameters, new byte[8]));
    } else {
      bufferedBlockCipher.init(paramBoolean, paramCipherParameters);
    } 
    return bufferedBlockCipher;
  }
  
  private static AEADBlockCipher createAEADCipher(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    if (NISTObjectIdentifiers.id_aes128_GCM.equals(paramASN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes192_GCM.equals(paramASN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes256_GCM.equals(paramASN1ObjectIdentifier))
      return new GCMBlockCipher(new AESEngine()); 
    if (NISTObjectIdentifiers.id_aes128_CCM.equals(paramASN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes192_CCM.equals(paramASN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes256_CCM.equals(paramASN1ObjectIdentifier))
      return new CCMBlockCipher(new AESEngine()); 
    throw new IllegalArgumentException("cannot recognise cipher: " + paramASN1ObjectIdentifier);
  }
  
  private static BufferedBlockCipher createCipher(ASN1ObjectIdentifier paramASN1ObjectIdentifier) throws IllegalArgumentException {
    CBCBlockCipher cBCBlockCipher;
    if (NISTObjectIdentifiers.id_aes128_CBC.equals(paramASN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes192_CBC.equals(paramASN1ObjectIdentifier) || NISTObjectIdentifiers.id_aes256_CBC.equals(paramASN1ObjectIdentifier)) {
      cBCBlockCipher = new CBCBlockCipher(new AESEngine());
    } else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(paramASN1ObjectIdentifier)) {
      cBCBlockCipher = new CBCBlockCipher(new DESedeEngine());
    } else if (OIWObjectIdentifiers.desCBC.equals(paramASN1ObjectIdentifier)) {
      cBCBlockCipher = new CBCBlockCipher(new DESEngine());
    } else if (PKCSObjectIdentifiers.RC2_CBC.equals(paramASN1ObjectIdentifier)) {
      cBCBlockCipher = new CBCBlockCipher(new RC2Engine());
    } else if (MiscObjectIdentifiers.cast5CBC.equals(paramASN1ObjectIdentifier)) {
      cBCBlockCipher = new CBCBlockCipher(new CAST5Engine());
    } else {
      throw new IllegalArgumentException("cannot recognise cipher: " + paramASN1ObjectIdentifier);
    } 
    return new PaddedBufferedBlockCipher(cBCBlockCipher, new PKCS7Padding());
  }
  
  public static CipherOutputStream createOutputStream(OutputStream paramOutputStream, Object paramObject) {
    if (paramObject instanceof BufferedBlockCipher)
      return new CipherOutputStream(paramOutputStream, (BufferedBlockCipher)paramObject); 
    if (paramObject instanceof StreamCipher)
      return new CipherOutputStream(paramOutputStream, (StreamCipher)paramObject); 
    if (paramObject instanceof AEADBlockCipher)
      return new CipherOutputStream(paramOutputStream, (AEADBlockCipher)paramObject); 
    throw new IllegalArgumentException("unknown cipher object: " + paramObject);
  }
}
