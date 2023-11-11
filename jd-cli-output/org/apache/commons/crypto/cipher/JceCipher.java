package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

class JceCipher implements CryptoCipher {
  private final Cipher cipher;
  
  public JceCipher(Properties props, String transformation) throws GeneralSecurityException {
    String provider = props.getProperty("commons.crypto.cipher.jce.provider");
    if (provider == null || provider.isEmpty()) {
      this.cipher = Cipher.getInstance(transformation);
    } else {
      this.cipher = Cipher.getInstance(transformation, provider);
    } 
  }
  
  public final int getBlockSize() {
    return this.cipher.getBlockSize();
  }
  
  public String getAlgorithm() {
    return this.cipher.getAlgorithm();
  }
  
  public void init(int mode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(params, "params");
    this.cipher.init(mode, key, params);
  }
  
  public int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws ShortBufferException {
    return this.cipher.update(inBuffer, outBuffer);
  }
  
  public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    return this.cipher
      .update(input, inputOffset, inputLen, output, outputOffset);
  }
  
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    return this.cipher.doFinal(inBuffer, outBuffer);
  }
  
  public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    return this.cipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
  }
  
  public void updateAAD(byte[] aad) {
    this.cipher.updateAAD(aad);
  }
  
  public void updateAAD(ByteBuffer aad) {
    this.cipher.updateAAD(aad);
  }
  
  public void close() {}
}
