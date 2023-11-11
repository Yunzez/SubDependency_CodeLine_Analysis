package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.util.BadBlockException;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class GMCipherSpi extends CipherSpi {
  private final JcaJceHelper helper = new BCJcaJceHelper();
  
  private SM2Engine engine;
  
  private int state = -1;
  
  private ErasableOutputStream buffer = new ErasableOutputStream();
  
  private AsymmetricKeyParameter key;
  
  private SecureRandom random;
  
  public GMCipherSpi(SM2Engine paramSM2Engine) {
    this.engine = paramSM2Engine;
  }
  
  public int engineGetBlockSize() {
    return 0;
  }
  
  public int engineGetKeySize(Key paramKey) {
    if (paramKey instanceof ECKey)
      return ((ECKey)paramKey).getParameters().getCurve().getFieldSize(); 
    throw new IllegalArgumentException("not an EC key");
  }
  
  public byte[] engineGetIV() {
    return null;
  }
  
  public AlgorithmParameters engineGetParameters() {
    return null;
  }
  
  public void engineSetMode(String paramString) throws NoSuchAlgorithmException {
    String str = Strings.toUpperCase(paramString);
    if (!str.equals("NONE"))
      throw new IllegalArgumentException("can't support mode " + paramString); 
  }
  
  public int engineGetOutputSize(int paramInt) {
    if (this.state == 1 || this.state == 3)
      return this.engine.getOutputSize(paramInt); 
    if (this.state == 2 || this.state == 4)
      return this.engine.getOutputSize(paramInt); 
    throw new IllegalStateException("cipher not initialised");
  }
  
  public void engineSetPadding(String paramString) throws NoSuchPaddingException {
    String str = Strings.toUpperCase(paramString);
    if (!str.equals("NOPADDING"))
      throw new NoSuchPaddingException("padding not available with IESCipher"); 
  }
  
  public void engineInit(int paramInt, Key paramKey, AlgorithmParameters paramAlgorithmParameters, SecureRandom paramSecureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
    AlgorithmParameterSpec algorithmParameterSpec = null;
    if (paramAlgorithmParameters != null)
      throw new InvalidAlgorithmParameterException("cannot recognise parameters: " + paramAlgorithmParameters.getClass().getName()); 
    engineInit(paramInt, paramKey, algorithmParameterSpec, paramSecureRandom);
  }
  
  public void engineInit(int paramInt, Key paramKey, AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException, InvalidKeyException {
    if (paramInt == 1 || paramInt == 3) {
      if (paramKey instanceof PublicKey) {
        this.key = ECUtils.generatePublicKeyParameter((PublicKey)paramKey);
      } else {
        throw new InvalidKeyException("must be passed public EC key for encryption");
      } 
    } else if (paramInt == 2 || paramInt == 4) {
      if (paramKey instanceof PrivateKey) {
        this.key = ECUtil.generatePrivateKeyParameter((PrivateKey)paramKey);
      } else {
        throw new InvalidKeyException("must be passed private EC key for decryption");
      } 
    } else {
      throw new InvalidKeyException("must be passed EC key");
    } 
    if (paramSecureRandom != null) {
      this.random = paramSecureRandom;
    } else {
      this.random = CryptoServicesRegistrar.getSecureRandom();
    } 
    this.state = paramInt;
    this.buffer.reset();
  }
  
  public void engineInit(int paramInt, Key paramKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    try {
      engineInit(paramInt, paramKey, (AlgorithmParameterSpec)null, paramSecureRandom);
    } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
      throw new IllegalArgumentException("cannot handle supplied parameter spec: " + invalidAlgorithmParameterException.getMessage());
    } 
  }
  
  public byte[] engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.buffer.write(paramArrayOfbyte, paramInt1, paramInt2);
    return null;
  }
  
  public int engineUpdate(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    this.buffer.write(paramArrayOfbyte1, paramInt1, paramInt2);
    return 0;
  }
  
  public byte[] engineDoFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IllegalBlockSizeException, BadPaddingException {
    if (paramInt2 != 0)
      this.buffer.write(paramArrayOfbyte, paramInt1, paramInt2); 
    try {
      if (this.state == 1 || this.state == 3)
        try {
          this.engine.init(true, new ParametersWithRandom(this.key, this.random));
          return this.engine.processBlock(this.buffer.getBuf(), 0, this.buffer.size());
        } catch (Exception exception) {
          throw new BadBlockException("unable to process block", exception);
        }  
      if (this.state == 2 || this.state == 4)
        try {
          this.engine.init(false, this.key);
          return this.engine.processBlock(this.buffer.getBuf(), 0, this.buffer.size());
        } catch (Exception exception) {
          throw new BadBlockException("unable to process block", exception);
        }  
      throw new IllegalStateException("cipher not initialised");
    } finally {
      this.buffer.erase();
    } 
  }
  
  public int engineDoFinal(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] arrayOfByte = engineDoFinal(paramArrayOfbyte1, paramInt1, paramInt2);
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt3, arrayOfByte.length);
    return arrayOfByte.length;
  }
  
  protected static final class ErasableOutputStream extends ByteArrayOutputStream {
    public byte[] getBuf() {
      return this.buf;
    }
    
    public void erase() {
      Arrays.fill(this.buf, (byte)0);
      reset();
    }
  }
  
  public static class SM2 extends GMCipherSpi {
    public SM2() {
      super(new SM2Engine());
    }
  }
  
  public static class SM2withBlake2b extends GMCipherSpi {
    public SM2withBlake2b() {
      super(new SM2Engine(new Blake2bDigest(512)));
    }
  }
  
  public static class SM2withBlake2s extends GMCipherSpi {
    public SM2withBlake2s() {
      super(new SM2Engine(new Blake2sDigest(256)));
    }
  }
  
  public static class SM2withMD5 extends GMCipherSpi {
    public SM2withMD5() {
      super(new SM2Engine(new MD5Digest()));
    }
  }
  
  public static class SM2withRMD extends GMCipherSpi {
    public SM2withRMD() {
      super(new SM2Engine(new RIPEMD160Digest()));
    }
  }
  
  public static class SM2withSha1 extends GMCipherSpi {
    public SM2withSha1() {
      super(new SM2Engine(new SHA1Digest()));
    }
  }
  
  public static class SM2withSha224 extends GMCipherSpi {
    public SM2withSha224() {
      super(new SM2Engine(new SHA224Digest()));
    }
  }
  
  public static class SM2withSha256 extends GMCipherSpi {
    public SM2withSha256() {
      super(new SM2Engine(new SHA256Digest()));
    }
  }
  
  public static class SM2withSha384 extends GMCipherSpi {
    public SM2withSha384() {
      super(new SM2Engine(new SHA384Digest()));
    }
  }
  
  public static class SM2withSha512 extends GMCipherSpi {
    public SM2withSha512() {
      super(new SM2Engine(new SHA512Digest()));
    }
  }
  
  public static class SM2withWhirlpool extends GMCipherSpi {
    public SM2withWhirlpool() {
      super(new SM2Engine(new WhirlpoolDigest()));
    }
  }
}
