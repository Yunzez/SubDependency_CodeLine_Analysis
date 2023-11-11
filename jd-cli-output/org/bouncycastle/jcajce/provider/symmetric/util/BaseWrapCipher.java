package org.bouncycastle.jcajce.provider.symmetric.util;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.crypto.params.ParametersWithUKM;
import org.bouncycastle.jcajce.spec.GOST28147WrapParameterSpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public abstract class BaseWrapCipher extends CipherSpi implements PBE {
  private Class[] availableSpecs = new Class[] { GOST28147WrapParameterSpec.class, PBEParameterSpec.class, RC2ParameterSpec.class, RC5ParameterSpec.class, IvParameterSpec.class };
  
  protected int pbeType = 2;
  
  protected int pbeHash = 1;
  
  protected int pbeKeySize;
  
  protected int pbeIvSize;
  
  protected AlgorithmParameters engineParams = null;
  
  protected Wrapper wrapEngine = null;
  
  private int ivSize;
  
  private byte[] iv;
  
  private ErasableOutputStream wrapStream = null;
  
  private boolean forWrapping;
  
  private final JcaJceHelper helper = new BCJcaJceHelper();
  
  protected BaseWrapCipher() {}
  
  protected BaseWrapCipher(Wrapper paramWrapper) {
    this(paramWrapper, 0);
  }
  
  protected BaseWrapCipher(Wrapper paramWrapper, int paramInt) {
    this.wrapEngine = paramWrapper;
    this.ivSize = paramInt;
  }
  
  protected int engineGetBlockSize() {
    return 0;
  }
  
  protected byte[] engineGetIV() {
    return Arrays.clone(this.iv);
  }
  
  protected int engineGetKeySize(Key paramKey) {
    return (paramKey.getEncoded()).length * 8;
  }
  
  protected int engineGetOutputSize(int paramInt) {
    return -1;
  }
  
  protected AlgorithmParameters engineGetParameters() {
    if (this.engineParams == null && this.iv != null) {
      String str = this.wrapEngine.getAlgorithmName();
      if (str.indexOf('/') >= 0)
        str = str.substring(0, str.indexOf('/')); 
      try {
        this.engineParams = createParametersInstance(str);
        this.engineParams.init(new IvParameterSpec(this.iv));
      } catch (Exception exception) {
        throw new RuntimeException(exception.toString());
      } 
    } 
    return this.engineParams;
  }
  
  protected final AlgorithmParameters createParametersInstance(String paramString) throws NoSuchAlgorithmException, NoSuchProviderException {
    return this.helper.createAlgorithmParameters(paramString);
  }
  
  protected void engineSetMode(String paramString) throws NoSuchAlgorithmException {
    throw new NoSuchAlgorithmException("can't support mode " + paramString);
  }
  
  protected void engineSetPadding(String paramString) throws NoSuchPaddingException {
    throw new NoSuchPaddingException("Padding " + paramString + " unknown.");
  }
  
  protected void engineInit(int paramInt, Key paramKey, AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
    CipherParameters cipherParameters;
    if (paramKey instanceof BCPBEKey) {
      BCPBEKey bCPBEKey = (BCPBEKey)paramKey;
      if (paramAlgorithmParameterSpec instanceof PBEParameterSpec) {
        cipherParameters = PBE.Util.makePBEParameters(bCPBEKey, paramAlgorithmParameterSpec, this.wrapEngine.getAlgorithmName());
      } else if (bCPBEKey.getParam() != null) {
        cipherParameters = bCPBEKey.getParam();
      } else {
        throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
      } 
    } else {
      cipherParameters = new KeyParameter(paramKey.getEncoded());
    } 
    if (paramAlgorithmParameterSpec instanceof IvParameterSpec) {
      IvParameterSpec ivParameterSpec = (IvParameterSpec)paramAlgorithmParameterSpec;
      this.iv = ivParameterSpec.getIV();
      cipherParameters = new ParametersWithIV(cipherParameters, this.iv);
    } 
    if (paramAlgorithmParameterSpec instanceof GOST28147WrapParameterSpec) {
      GOST28147WrapParameterSpec gOST28147WrapParameterSpec = (GOST28147WrapParameterSpec)paramAlgorithmParameterSpec;
      byte[] arrayOfByte = gOST28147WrapParameterSpec.getSBox();
      if (arrayOfByte != null)
        cipherParameters = new ParametersWithSBox(cipherParameters, arrayOfByte); 
      cipherParameters = new ParametersWithUKM(cipherParameters, gOST28147WrapParameterSpec.getUKM());
    } 
    if (cipherParameters instanceof KeyParameter && this.ivSize != 0 && (paramInt == 3 || paramInt == 1)) {
      this.iv = new byte[this.ivSize];
      paramSecureRandom.nextBytes(this.iv);
      cipherParameters = new ParametersWithIV(cipherParameters, this.iv);
    } 
    if (paramSecureRandom != null)
      cipherParameters = new ParametersWithRandom(cipherParameters, paramSecureRandom); 
    try {
      switch (paramInt) {
        case 3:
          this.wrapEngine.init(true, cipherParameters);
          this.wrapStream = null;
          this.forWrapping = true;
          return;
        case 4:
          this.wrapEngine.init(false, cipherParameters);
          this.wrapStream = null;
          this.forWrapping = false;
          return;
        case 1:
          this.wrapEngine.init(true, cipherParameters);
          this.wrapStream = new ErasableOutputStream();
          this.forWrapping = true;
          return;
        case 2:
          this.wrapEngine.init(false, cipherParameters);
          this.wrapStream = new ErasableOutputStream();
          this.forWrapping = false;
          return;
      } 
      throw new InvalidParameterException("Unknown mode parameter passed to init.");
    } catch (Exception exception) {
      throw new InvalidKeyOrParametersException(exception.getMessage(), exception);
    } 
  }
  
  protected void engineInit(int paramInt, Key paramKey, AlgorithmParameters paramAlgorithmParameters, SecureRandom paramSecureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
    AlgorithmParameterSpec algorithmParameterSpec = null;
    if (paramAlgorithmParameters != null) {
      algorithmParameterSpec = SpecUtil.extractSpec(paramAlgorithmParameters, this.availableSpecs);
      if (algorithmParameterSpec == null)
        throw new InvalidAlgorithmParameterException("can't handle parameter " + paramAlgorithmParameters.toString()); 
    } 
    this.engineParams = paramAlgorithmParameters;
    engineInit(paramInt, paramKey, algorithmParameterSpec, paramSecureRandom);
  }
  
  protected void engineInit(int paramInt, Key paramKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    try {
      engineInit(paramInt, paramKey, (AlgorithmParameterSpec)null, paramSecureRandom);
    } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
      throw new InvalidKeyOrParametersException(invalidAlgorithmParameterException.getMessage(), invalidAlgorithmParameterException);
    } 
  }
  
  protected byte[] engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.wrapStream == null)
      throw new IllegalStateException("not supported in a wrapping mode"); 
    this.wrapStream.write(paramArrayOfbyte, paramInt1, paramInt2);
    return null;
  }
  
  protected int engineUpdate(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws ShortBufferException {
    if (this.wrapStream == null)
      throw new IllegalStateException("not supported in a wrapping mode"); 
    this.wrapStream.write(paramArrayOfbyte1, paramInt1, paramInt2);
    return 0;
  }
  
  protected byte[] engineDoFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IllegalBlockSizeException, BadPaddingException {
    if (this.wrapStream == null)
      throw new IllegalStateException("not supported in a wrapping mode"); 
    if (paramArrayOfbyte != null)
      this.wrapStream.write(paramArrayOfbyte, paramInt1, paramInt2); 
    try {
      if (this.forWrapping)
        try {
          return this.wrapEngine.wrap(this.wrapStream.getBuf(), 0, this.wrapStream.size());
        } catch (Exception exception) {
          throw new IllegalBlockSizeException(exception.getMessage());
        }  
    } finally {
      this.wrapStream.erase();
    } 
  }
  
  protected int engineDoFinal(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException {
    if (this.wrapStream == null)
      throw new IllegalStateException("not supported in a wrapping mode"); 
    this.wrapStream.write(paramArrayOfbyte1, paramInt1, paramInt2);
    try {
      byte[] arrayOfByte;
      if (this.forWrapping) {
        try {
          arrayOfByte = this.wrapEngine.wrap(this.wrapStream.getBuf(), 0, this.wrapStream.size());
        } catch (Exception exception) {
          throw new IllegalBlockSizeException(exception.getMessage());
        } 
      } else {
        try {
          arrayOfByte = this.wrapEngine.unwrap(this.wrapStream.getBuf(), 0, this.wrapStream.size());
        } catch (InvalidCipherTextException invalidCipherTextException) {
          throw new BadPaddingException(invalidCipherTextException.getMessage());
        } 
      } 
      if (paramInt3 + arrayOfByte.length > paramArrayOfbyte2.length)
        throw new ShortBufferException("output buffer too short for input."); 
      System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt3, arrayOfByte.length);
      return arrayOfByte.length;
    } finally {
      this.wrapStream.erase();
    } 
  }
  
  protected byte[] engineWrap(Key paramKey) throws IllegalBlockSizeException, InvalidKeyException {
    byte[] arrayOfByte = paramKey.getEncoded();
    if (arrayOfByte == null)
      throw new InvalidKeyException("Cannot wrap key, null encoding."); 
    try {
      return (this.wrapEngine == null) ? engineDoFinal(arrayOfByte, 0, arrayOfByte.length) : this.wrapEngine.wrap(arrayOfByte, 0, arrayOfByte.length);
    } catch (BadPaddingException badPaddingException) {
      throw new IllegalBlockSizeException(badPaddingException.getMessage());
    } 
  }
  
  protected Key engineUnwrap(byte[] paramArrayOfbyte, String paramString, int paramInt) throws InvalidKeyException, NoSuchAlgorithmException {
    byte[] arrayOfByte;
    try {
      if (this.wrapEngine == null) {
        arrayOfByte = engineDoFinal(paramArrayOfbyte, 0, paramArrayOfbyte.length);
      } else {
        arrayOfByte = this.wrapEngine.unwrap(paramArrayOfbyte, 0, paramArrayOfbyte.length);
      } 
    } catch (InvalidCipherTextException invalidCipherTextException) {
      throw new InvalidKeyException(invalidCipherTextException.getMessage());
    } catch (BadPaddingException badPaddingException) {
      throw new InvalidKeyException(badPaddingException.getMessage());
    } catch (IllegalBlockSizeException illegalBlockSizeException) {
      throw new InvalidKeyException(illegalBlockSizeException.getMessage());
    } 
    if (paramInt == 3)
      return new SecretKeySpec(arrayOfByte, paramString); 
    if (paramString.equals("") && paramInt == 2)
      try {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(arrayOfByte);
        PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(privateKeyInfo);
        if (privateKey != null)
          return privateKey; 
        throw new InvalidKeyException("algorithm " + privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm() + " not supported");
      } catch (Exception exception) {
        throw new InvalidKeyException("Invalid key encoding.");
      }  
    try {
      KeyFactory keyFactory = this.helper.createKeyFactory(paramString);
      if (paramInt == 1)
        return keyFactory.generatePublic(new X509EncodedKeySpec(arrayOfByte)); 
      if (paramInt == 2)
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(arrayOfByte)); 
    } catch (NoSuchProviderException noSuchProviderException) {
      throw new InvalidKeyException("Unknown key type " + noSuchProviderException.getMessage());
    } catch (InvalidKeySpecException invalidKeySpecException) {
      throw new InvalidKeyException("Unknown key type " + invalidKeySpecException.getMessage());
    } 
    throw new InvalidKeyException("Unknown key type " + paramInt);
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
  
  protected static class InvalidKeyOrParametersException extends InvalidKeyException {
    private final Throwable cause;
    
    InvalidKeyOrParametersException(String param1String, Throwable param1Throwable) {
      super(param1String);
      this.cause = param1Throwable;
    }
    
    public Throwable getCause() {
      return this.cause;
    }
  }
}
