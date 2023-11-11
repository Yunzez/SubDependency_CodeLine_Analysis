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
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

class OpenSslCipher implements CryptoCipher {
  private final OpenSsl openSslEngine;
  
  private boolean initialized = false;
  
  private final String transformation;
  
  public OpenSslCipher(Properties props, String transformation) throws GeneralSecurityException {
    this.transformation = transformation;
    Throwable loadingFailureReason = OpenSsl.getLoadingFailureReason();
    if (loadingFailureReason != null)
      throw new IllegalStateException(loadingFailureReason); 
    this.openSslEngine = OpenSsl.getInstance(transformation);
  }
  
  public final int getBlockSize() {
    return 16;
  }
  
  public String getAlgorithm() {
    return this.transformation;
  }
  
  public void init(int mode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(params, "params");
    int cipherMode = 0;
    if (mode == 1)
      cipherMode = 1; 
    this.openSslEngine.init(cipherMode, key.getEncoded(), params);
    this.initialized = true;
  }
  
  public int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws ShortBufferException {
    return this.openSslEngine.update(inBuffer, outBuffer);
  }
  
  public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    return this.openSslEngine
      .update(input, inputOffset, inputLen, output, outputOffset);
  }
  
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    return this.openSslEngine.doFinal(inBuffer, outBuffer);
  }
  
  public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    return this.openSslEngine.doFinal(input, inputOffset, inputLen, output, outputOffset);
  }
  
  public void updateAAD(byte[] aad) throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
    if (aad == null)
      throw new IllegalArgumentException("aad buffer is null"); 
    if (!this.initialized)
      throw new IllegalStateException("Cipher not initialized"); 
    if (aad.length == 0)
      return; 
    this.openSslEngine.updateAAD(aad);
  }
  
  public void updateAAD(ByteBuffer aad) throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
    if (aad == null)
      throw new IllegalArgumentException("aad buffer is null"); 
    if (!this.initialized)
      throw new IllegalStateException("Cipher not initialized"); 
    int aadLen = aad.limit() - aad.position();
    if (aadLen == 0)
      return; 
    byte[] aadBytes = new byte[aadLen];
    aad.get(aadBytes);
    this.openSslEngine.updateAAD(aadBytes);
  }
  
  public void close() {
    this.openSslEngine.clean();
  }
}
