package org.bouncycastle.pqc.crypto.newhope;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.ExchangePair;
import org.bouncycastle.util.Arrays;

public class NHSecretKeyProcessor {
  private final Xof xof = new SHAKEDigest(256);
  
  private NHSecretKeyProcessor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.xof.update(paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
    if (paramArrayOfbyte2 != null)
      this.xof.update(paramArrayOfbyte2, 0, paramArrayOfbyte2.length); 
    Arrays.fill(paramArrayOfbyte1, (byte)0);
  }
  
  public byte[] processKey(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte.length];
    this.xof.doFinal(arrayOfByte, 0, arrayOfByte.length);
    xor(paramArrayOfbyte, arrayOfByte);
    Arrays.fill(arrayOfByte, (byte)0);
    return paramArrayOfbyte;
  }
  
  private static void xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    for (byte b = 0; b != paramArrayOfbyte1.length; b++)
      paramArrayOfbyte1[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]); 
  }
  
  public static class PartyUBuilder {
    private final AsymmetricCipherKeyPair aKp;
    
    private final NHAgreement agreement = new NHAgreement();
    
    private byte[] sharedInfo = null;
    
    private boolean used = false;
    
    public PartyUBuilder(SecureRandom param1SecureRandom) {
      NHKeyPairGenerator nHKeyPairGenerator = new NHKeyPairGenerator();
      nHKeyPairGenerator.init(new KeyGenerationParameters(param1SecureRandom, 2048));
      this.aKp = nHKeyPairGenerator.generateKeyPair();
      this.agreement.init(this.aKp.getPrivate());
    }
    
    public PartyUBuilder withSharedInfo(byte[] param1ArrayOfbyte) {
      this.sharedInfo = Arrays.clone(param1ArrayOfbyte);
      return this;
    }
    
    public byte[] getPartA() {
      return ((NHPublicKeyParameters)this.aKp.getPublic()).getPubData();
    }
    
    public NHSecretKeyProcessor build(byte[] param1ArrayOfbyte) {
      if (this.used)
        throw new IllegalStateException("builder already used"); 
      this.used = true;
      return new NHSecretKeyProcessor(this.agreement.calculateAgreement(new NHPublicKeyParameters(param1ArrayOfbyte)), this.sharedInfo);
    }
  }
  
  public static class PartyVBuilder {
    protected final SecureRandom random;
    
    private byte[] sharedInfo = null;
    
    private byte[] sharedSecret = null;
    
    private boolean used = false;
    
    public PartyVBuilder(SecureRandom param1SecureRandom) {
      this.random = param1SecureRandom;
    }
    
    public PartyVBuilder withSharedInfo(byte[] param1ArrayOfbyte) {
      this.sharedInfo = Arrays.clone(param1ArrayOfbyte);
      return this;
    }
    
    public byte[] getPartB(byte[] param1ArrayOfbyte) {
      NHExchangePairGenerator nHExchangePairGenerator = new NHExchangePairGenerator(this.random);
      ExchangePair exchangePair = nHExchangePairGenerator.generateExchange(new NHPublicKeyParameters(param1ArrayOfbyte));
      this.sharedSecret = exchangePair.getSharedValue();
      return ((NHPublicKeyParameters)exchangePair.getPublicKey()).getPubData();
    }
    
    public NHSecretKeyProcessor build() {
      if (this.used)
        throw new IllegalStateException("builder already used"); 
      this.used = true;
      return new NHSecretKeyProcessor(this.sharedSecret, this.sharedInfo);
    }
  }
}
