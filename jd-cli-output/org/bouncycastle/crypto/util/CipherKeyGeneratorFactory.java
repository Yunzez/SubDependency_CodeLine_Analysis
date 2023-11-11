package org.bouncycastle.crypto.util;

import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.generators.DESedeKeyGenerator;

public class CipherKeyGeneratorFactory {
  public static CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier paramASN1ObjectIdentifier, SecureRandom paramSecureRandom) throws IllegalArgumentException {
    if (NISTObjectIdentifiers.id_aes128_CBC.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (NISTObjectIdentifiers.id_aes192_CBC.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 192); 
    if (NISTObjectIdentifiers.id_aes256_CBC.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 256); 
    if (NISTObjectIdentifiers.id_aes128_GCM.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (NISTObjectIdentifiers.id_aes192_GCM.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 192); 
    if (NISTObjectIdentifiers.id_aes256_GCM.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 256); 
    if (NISTObjectIdentifiers.id_aes128_CCM.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (NISTObjectIdentifiers.id_aes192_CCM.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 192); 
    if (NISTObjectIdentifiers.id_aes256_CCM.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 256); 
    if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(paramASN1ObjectIdentifier)) {
      DESedeKeyGenerator dESedeKeyGenerator = new DESedeKeyGenerator();
      dESedeKeyGenerator.init(new KeyGenerationParameters(paramSecureRandom, 192));
      return dESedeKeyGenerator;
    } 
    if (NTTObjectIdentifiers.id_camellia128_cbc.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (NTTObjectIdentifiers.id_camellia192_cbc.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 192); 
    if (NTTObjectIdentifiers.id_camellia256_cbc.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 256); 
    if (KISAObjectIdentifiers.id_seedCBC.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (AlgorithmIdentifierFactory.CAST5_CBC.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (OIWObjectIdentifiers.desCBC.equals(paramASN1ObjectIdentifier)) {
      DESKeyGenerator dESKeyGenerator = new DESKeyGenerator();
      dESKeyGenerator.init(new KeyGenerationParameters(paramSecureRandom, 64));
      return dESKeyGenerator;
    } 
    if (PKCSObjectIdentifiers.rc4.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    if (PKCSObjectIdentifiers.RC2_CBC.equals(paramASN1ObjectIdentifier))
      return createCipherKeyGenerator(paramSecureRandom, 128); 
    throw new IllegalArgumentException("cannot recognise cipher: " + paramASN1ObjectIdentifier);
  }
  
  private static CipherKeyGenerator createCipherKeyGenerator(SecureRandom paramSecureRandom, int paramInt) {
    CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();
    cipherKeyGenerator.init(new KeyGenerationParameters(paramSecureRandom, paramInt));
    return cipherKeyGenerator;
  }
}
