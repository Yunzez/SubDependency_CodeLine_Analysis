package org.bouncycastle.pqc.crypto.newhope;

import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.util.DEROtherInfo;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.ExchangePair;

public class NHOtherInfoGenerator {
  protected final DEROtherInfo.Builder otherInfoBuilder;
  
  protected final SecureRandom random;
  
  protected boolean used = false;
  
  public NHOtherInfoGenerator(AlgorithmIdentifier paramAlgorithmIdentifier, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, SecureRandom paramSecureRandom) {
    this.otherInfoBuilder = new DEROtherInfo.Builder(paramAlgorithmIdentifier, paramArrayOfbyte1, paramArrayOfbyte2);
    this.random = paramSecureRandom;
  }
  
  private static byte[] getEncoded(NHPublicKeyParameters paramNHPublicKeyParameters) {
    try {
      AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.newHope);
      SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, paramNHPublicKeyParameters.getPubData());
      return subjectPublicKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  private static NHPublicKeyParameters getPublicKey(byte[] paramArrayOfbyte) {
    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(paramArrayOfbyte);
    return new NHPublicKeyParameters(subjectPublicKeyInfo.getPublicKeyData().getOctets());
  }
  
  public static class PartyU extends NHOtherInfoGenerator {
    private AsymmetricCipherKeyPair aKp;
    
    private NHAgreement agreement = new NHAgreement();
    
    public PartyU(AlgorithmIdentifier param1AlgorithmIdentifier, byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2, SecureRandom param1SecureRandom) {
      super(param1AlgorithmIdentifier, param1ArrayOfbyte1, param1ArrayOfbyte2, param1SecureRandom);
      NHKeyPairGenerator nHKeyPairGenerator = new NHKeyPairGenerator();
      nHKeyPairGenerator.init(new KeyGenerationParameters(param1SecureRandom, 2048));
      this.aKp = nHKeyPairGenerator.generateKeyPair();
      this.agreement.init(this.aKp.getPrivate());
    }
    
    public NHOtherInfoGenerator withSuppPubInfo(byte[] param1ArrayOfbyte) {
      this.otherInfoBuilder.withSuppPubInfo(param1ArrayOfbyte);
      return this;
    }
    
    public byte[] getSuppPrivInfoPartA() {
      return NHOtherInfoGenerator.getEncoded((NHPublicKeyParameters)this.aKp.getPublic());
    }
    
    public DEROtherInfo generate(byte[] param1ArrayOfbyte) {
      if (this.used)
        throw new IllegalStateException("builder already used"); 
      this.used = true;
      this.otherInfoBuilder.withSuppPrivInfo(this.agreement.calculateAgreement(NHOtherInfoGenerator.getPublicKey(param1ArrayOfbyte)));
      return this.otherInfoBuilder.build();
    }
  }
  
  public static class PartyV extends NHOtherInfoGenerator {
    public PartyV(AlgorithmIdentifier param1AlgorithmIdentifier, byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2, SecureRandom param1SecureRandom) {
      super(param1AlgorithmIdentifier, param1ArrayOfbyte1, param1ArrayOfbyte2, param1SecureRandom);
    }
    
    public NHOtherInfoGenerator withSuppPubInfo(byte[] param1ArrayOfbyte) {
      this.otherInfoBuilder.withSuppPubInfo(param1ArrayOfbyte);
      return this;
    }
    
    public byte[] getSuppPrivInfoPartB(byte[] param1ArrayOfbyte) {
      NHExchangePairGenerator nHExchangePairGenerator = new NHExchangePairGenerator(this.random);
      ExchangePair exchangePair = nHExchangePairGenerator.generateExchange(NHOtherInfoGenerator.getPublicKey(param1ArrayOfbyte));
      this.otherInfoBuilder.withSuppPrivInfo(exchangePair.getSharedValue());
      return NHOtherInfoGenerator.getEncoded((NHPublicKeyParameters)exchangePair.getPublicKey());
    }
    
    public DEROtherInfo generate() {
      if (this.used)
        throw new IllegalStateException("builder already used"); 
      this.used = true;
      return this.otherInfoBuilder.build();
    }
  }
}
