package org.apache.commons.crypto.jna;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;
import java.util.StringTokenizer;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.cipher.CryptoCipher;

class OpenSslJnaCipher implements CryptoCipher {
  private PointerByReference algo;
  
  private final PointerByReference context;
  
  private final AlgorithmMode algMode;
  
  private final int padding;
  
  private final String transformation;
  
  private final int IV_LENGTH = 16;
  
  public OpenSslJnaCipher(Properties props, String transformation) throws GeneralSecurityException {
    if (!OpenSslJna.isEnabled())
      throw new GeneralSecurityException("Could not enable JNA access", OpenSslJna.initialisationError()); 
    this.transformation = transformation;
    Transform transform = tokenizeTransformation(transformation);
    this.algMode = AlgorithmMode.get(transform.algorithm, transform.mode);
    if (this.algMode != AlgorithmMode.AES_CBC && this.algMode != AlgorithmMode.AES_CTR)
      throw new GeneralSecurityException("unknown algorithm " + transform.algorithm + "_" + transform.mode); 
    this.padding = Padding.get(transform.padding);
    this.context = OpenSslNativeJna.EVP_CIPHER_CTX_new();
  }
  
  public void init(int mode, Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
    byte[] iv;
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(params, "params");
    int cipherMode = 0;
    if (mode == 1)
      cipherMode = 1; 
    if (params instanceof IvParameterSpec) {
      iv = ((IvParameterSpec)params).getIV();
    } else {
      throw new InvalidAlgorithmParameterException("Illegal parameters");
    } 
    if ((this.algMode == AlgorithmMode.AES_CBC || this.algMode == AlgorithmMode.AES_CTR) && iv.length != 16)
      throw new InvalidAlgorithmParameterException("Wrong IV length: must be 16 bytes long"); 
    if (this.algMode == AlgorithmMode.AES_CBC) {
      switch ((key.getEncoded()).length) {
        case 16:
          this.algo = OpenSslNativeJna.EVP_aes_128_cbc();
          break;
        case 24:
          this.algo = OpenSslNativeJna.EVP_aes_192_cbc();
          break;
        case 32:
          this.algo = OpenSslNativeJna.EVP_aes_256_cbc();
          break;
        default:
          throw new InvalidKeyException("keysize unsupported (" + (key.getEncoded()).length + ")");
      } 
    } else {
      switch ((key.getEncoded()).length) {
        case 16:
          this.algo = OpenSslNativeJna.EVP_aes_128_ctr();
          break;
        case 24:
          this.algo = OpenSslNativeJna.EVP_aes_192_ctr();
          break;
        case 32:
          this.algo = OpenSslNativeJna.EVP_aes_256_ctr();
          break;
        default:
          throw new InvalidKeyException("keysize unsupported (" + (key.getEncoded()).length + ")");
      } 
    } 
    int retVal = OpenSslNativeJna.EVP_CipherInit_ex(this.context, this.algo, null, key.getEncoded(), iv, cipherMode);
    throwOnError(retVal);
    OpenSslNativeJna.EVP_CIPHER_CTX_set_padding(this.context, this.padding);
  }
  
  public int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws ShortBufferException {
    int[] outlen = new int[1];
    int retVal = OpenSslNativeJna.EVP_CipherUpdate(this.context, outBuffer, outlen, inBuffer, inBuffer
        .remaining());
    throwOnError(retVal);
    int len = outlen[0];
    inBuffer.position(inBuffer.limit());
    outBuffer.position(outBuffer.position() + len);
    return len;
  }
  
  public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    ByteBuffer outputBuf = ByteBuffer.wrap(output, outputOffset, output.length - outputOffset);
    ByteBuffer inputBuf = ByteBuffer.wrap(input, inputOffset, inputLen);
    return update(inputBuf, outputBuf);
  }
  
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    int uptLen = update(inBuffer, outBuffer);
    int[] outlen = new int[1];
    int retVal = OpenSslNativeJna.EVP_CipherFinal_ex(this.context, outBuffer, outlen);
    throwOnError(retVal);
    int len = uptLen + outlen[0];
    outBuffer.position(outBuffer.position() + outlen[0]);
    return len;
  }
  
  public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    ByteBuffer outputBuf = ByteBuffer.wrap(output, outputOffset, output.length - outputOffset);
    ByteBuffer inputBuf = ByteBuffer.wrap(input, inputOffset, inputLen);
    return doFinal(inputBuf, outputBuf);
  }
  
  public void updateAAD(byte[] aad) throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
    throw new UnsupportedOperationException("This is unsupported in Jna Cipher");
  }
  
  public void updateAAD(ByteBuffer aad) throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
    throw new UnsupportedOperationException("This is unsupported in Jna Cipher");
  }
  
  public void close() {
    if (this.context != null)
      OpenSslNativeJna.EVP_CIPHER_CTX_cleanup(this.context); 
  }
  
  private void throwOnError(int retVal) {
    if (retVal != 1) {
      NativeLong err = OpenSslNativeJna.ERR_peek_error();
      String errdesc = OpenSslNativeJna.ERR_error_string(err, null);
      if (this.context != null)
        OpenSslNativeJna.EVP_CIPHER_CTX_cleanup(this.context); 
      throw new IllegalStateException("return code " + retVal + " from OpenSSL. Err code is " + err + ": " + errdesc);
    } 
  }
  
  private static class Transform {
    final String algorithm;
    
    final String mode;
    
    final String padding;
    
    public Transform(String algorithm, String mode, String padding) {
      this.algorithm = algorithm;
      this.mode = mode;
      this.padding = padding;
    }
  }
  
  private static Transform tokenizeTransformation(String transformation) throws NoSuchAlgorithmException {
    if (transformation == null)
      throw new NoSuchAlgorithmException("No transformation given."); 
    String[] parts = new String[3];
    int count = 0;
    StringTokenizer parser = new StringTokenizer(transformation, "/");
    while (parser.hasMoreTokens() && count < 3)
      parts[count++] = parser.nextToken().trim(); 
    if (count != 3 || parser.hasMoreTokens())
      throw new NoSuchAlgorithmException("Invalid transformation format: " + transformation); 
    return new Transform(parts[0], parts[1], parts[2]);
  }
  
  private enum AlgorithmMode {
    AES_CTR, AES_CBC;
    
    static AlgorithmMode get(String algorithm, String mode) throws NoSuchAlgorithmException {
      try {
        return valueOf(algorithm + "_" + mode);
      } catch (Exception e) {
        throw new NoSuchAlgorithmException("Doesn't support algorithm: " + algorithm + " and mode: " + mode);
      } 
    }
  }
  
  private enum Padding {
    NoPadding, PKCS5Padding;
    
    static int get(String padding) throws NoSuchPaddingException {
      try {
        return valueOf(padding).ordinal();
      } catch (Exception e) {
        throw new NoSuchPaddingException("Doesn't support padding: " + padding);
      } 
    }
  }
  
  public int getBlockSize() {
    return 16;
  }
  
  public String getAlgorithm() {
    return this.transformation;
  }
  
  protected void finalize() throws Throwable {
    OpenSslNativeJna.EVP_CIPHER_CTX_free(this.context);
    super.finalize();
  }
}
