package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.StringTokenizer;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.utils.Utils;

final class OpenSsl {
  public static final int ENCRYPT_MODE = 1;
  
  public static final int DECRYPT_MODE = 0;
  
  private final OpenSslFeedbackCipher opensslBlockCipher;
  
  private static final Throwable loadingFailureReason;
  
  private enum AlgorithmMode {
    AES_CTR, AES_CBC, AES_GCM;
    
    static int get(String algorithm, String mode) throws NoSuchAlgorithmException {
      try {
        return valueOf(algorithm + "_" + mode).ordinal();
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
  
  static {
    Throwable loadingFailure = null;
    try {
      if (Crypto.isNativeCodeLoaded()) {
        OpenSslNative.initIDs();
      } else {
        loadingFailure = Crypto.getLoadingError();
      } 
    } catch (Exception t) {
      loadingFailure = t;
    } catch (UnsatisfiedLinkError t) {
      loadingFailure = t;
    } finally {
      loadingFailureReason = loadingFailure;
    } 
  }
  
  public static Throwable getLoadingFailureReason() {
    return loadingFailureReason;
  }
  
  private OpenSsl(long context, int algorithm, int padding) {
    if (algorithm == AlgorithmMode.AES_GCM.ordinal()) {
      this.opensslBlockCipher = new OpenSslGaloisCounterMode(context, algorithm, padding);
    } else {
      this.opensslBlockCipher = new OpenSslCommonMode(context, algorithm, padding);
    } 
  }
  
  public static OpenSsl getInstance(String transformation) throws NoSuchAlgorithmException, NoSuchPaddingException {
    if (loadingFailureReason != null)
      throw new IllegalStateException(loadingFailureReason); 
    Transform transform = tokenizeTransformation(transformation);
    int algorithmMode = AlgorithmMode.get(transform.algorithm, transform.mode);
    int padding = Padding.get(transform.padding);
    long context = OpenSslNative.initContext(algorithmMode, padding);
    return new OpenSsl(context, algorithmMode, padding);
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
  
  public void init(int mode, byte[] key, AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    this.opensslBlockCipher.init(mode, key, params);
  }
  
  public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
    Utils.checkArgument((input.isDirect() && output.isDirect()), "Direct buffers are required.");
    return this.opensslBlockCipher.update(input, output);
  }
  
  public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    return this.opensslBlockCipher.update(input, inputOffset, inputLen, output, outputOffset);
  }
  
  public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    return this.opensslBlockCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
  }
  
  public int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    Utils.checkArgument(output.isDirect(), "Direct buffer is required.");
    return this.opensslBlockCipher.doFinal(input, output);
  }
  
  public void updateAAD(byte[] aad) {
    this.opensslBlockCipher.updateAAD(aad);
  }
  
  public void clean() {
    if (this.opensslBlockCipher != null)
      this.opensslBlockCipher.clean(); 
  }
  
  protected void finalize() throws Throwable {
    clean();
  }
}
