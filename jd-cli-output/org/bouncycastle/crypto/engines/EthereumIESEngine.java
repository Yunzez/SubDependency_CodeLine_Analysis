package org.bouncycastle.crypto.engines;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.IESWithCipherParameters;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

public class EthereumIESEngine {
  BasicAgreement agree;
  
  DerivationFunction kdf;
  
  Mac mac;
  
  BufferedBlockCipher cipher;
  
  byte[] macBuf;
  
  byte[] commonMac;
  
  boolean forEncryption;
  
  CipherParameters privParam;
  
  CipherParameters pubParam;
  
  IESParameters param;
  
  byte[] V;
  
  private EphemeralKeyPairGenerator keyPairGenerator;
  
  private KeyParser keyParser;
  
  private byte[] IV;
  
  public EthereumIESEngine(BasicAgreement paramBasicAgreement, DerivationFunction paramDerivationFunction, Mac paramMac, byte[] paramArrayOfbyte) {
    this.agree = paramBasicAgreement;
    this.kdf = paramDerivationFunction;
    this.mac = paramMac;
    this.macBuf = new byte[paramMac.getMacSize()];
    this.commonMac = paramArrayOfbyte;
    this.cipher = null;
  }
  
  public EthereumIESEngine(BasicAgreement paramBasicAgreement, DerivationFunction paramDerivationFunction, Mac paramMac, byte[] paramArrayOfbyte, BufferedBlockCipher paramBufferedBlockCipher) {
    this.agree = paramBasicAgreement;
    this.kdf = paramDerivationFunction;
    this.mac = paramMac;
    this.macBuf = new byte[paramMac.getMacSize()];
    this.commonMac = paramArrayOfbyte;
    this.cipher = paramBufferedBlockCipher;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters1, CipherParameters paramCipherParameters2, CipherParameters paramCipherParameters3) {
    this.forEncryption = paramBoolean;
    this.privParam = paramCipherParameters1;
    this.pubParam = paramCipherParameters2;
    this.V = new byte[0];
    extractParams(paramCipherParameters3);
  }
  
  public void init(AsymmetricKeyParameter paramAsymmetricKeyParameter, CipherParameters paramCipherParameters, EphemeralKeyPairGenerator paramEphemeralKeyPairGenerator) {
    this.forEncryption = true;
    this.pubParam = paramAsymmetricKeyParameter;
    this.keyPairGenerator = paramEphemeralKeyPairGenerator;
    extractParams(paramCipherParameters);
  }
  
  public void init(AsymmetricKeyParameter paramAsymmetricKeyParameter, CipherParameters paramCipherParameters, KeyParser paramKeyParser) {
    this.forEncryption = false;
    this.privParam = paramAsymmetricKeyParameter;
    this.keyParser = paramKeyParser;
    extractParams(paramCipherParameters);
  }
  
  private void extractParams(CipherParameters paramCipherParameters) {
    if (paramCipherParameters instanceof ParametersWithIV) {
      this.IV = ((ParametersWithIV)paramCipherParameters).getIV();
      this.param = (IESParameters)((ParametersWithIV)paramCipherParameters).getParameters();
    } else {
      this.IV = null;
      this.param = (IESParameters)paramCipherParameters;
    } 
  }
  
  public BufferedBlockCipher getCipher() {
    return this.cipher;
  }
  
  public Mac getMac() {
    return this.mac;
  }
  
  private byte[] encryptBlock(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    int i;
    byte[] arrayOfByte1 = null;
    byte[] arrayOfByte2 = null;
    byte[] arrayOfByte3 = null;
    byte[] arrayOfByte4 = null;
    if (this.cipher == null) {
      arrayOfByte3 = new byte[paramInt2];
      arrayOfByte4 = new byte[this.param.getMacKeySize() / 8];
      arrayOfByte2 = new byte[arrayOfByte3.length + arrayOfByte4.length];
      this.kdf.generateBytes(arrayOfByte2, 0, arrayOfByte2.length);
      if (this.V.length != 0) {
        System.arraycopy(arrayOfByte2, 0, arrayOfByte4, 0, arrayOfByte4.length);
        System.arraycopy(arrayOfByte2, arrayOfByte4.length, arrayOfByte3, 0, arrayOfByte3.length);
      } else {
        System.arraycopy(arrayOfByte2, 0, arrayOfByte3, 0, arrayOfByte3.length);
        System.arraycopy(arrayOfByte2, paramInt2, arrayOfByte4, 0, arrayOfByte4.length);
      } 
      arrayOfByte1 = new byte[paramInt2];
      for (int j = 0; j != paramInt2; j++)
        arrayOfByte1[j] = (byte)(paramArrayOfbyte[paramInt1 + j] ^ arrayOfByte3[j]); 
      i = paramInt2;
    } else {
      arrayOfByte3 = new byte[((IESWithCipherParameters)this.param).getCipherKeySize() / 8];
      arrayOfByte4 = new byte[this.param.getMacKeySize() / 8];
      arrayOfByte2 = new byte[arrayOfByte3.length + arrayOfByte4.length];
      this.kdf.generateBytes(arrayOfByte2, 0, arrayOfByte2.length);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte3, 0, arrayOfByte3.length);
      System.arraycopy(arrayOfByte2, arrayOfByte3.length, arrayOfByte4, 0, arrayOfByte4.length);
      if (this.IV != null) {
        this.cipher.init(true, new ParametersWithIV(new KeyParameter(arrayOfByte3), this.IV));
      } else {
        this.cipher.init(true, new KeyParameter(arrayOfByte3));
      } 
      arrayOfByte1 = new byte[this.cipher.getOutputSize(paramInt2)];
      i = this.cipher.processBytes(paramArrayOfbyte, paramInt1, paramInt2, arrayOfByte1, 0);
      i += this.cipher.doFinal(arrayOfByte1, i);
    } 
    byte[] arrayOfByte5 = this.param.getEncodingV();
    byte[] arrayOfByte6 = null;
    if (this.V.length != 0)
      arrayOfByte6 = getLengthTag(arrayOfByte5); 
    byte[] arrayOfByte7 = new byte[this.mac.getMacSize()];
    SHA256Digest sHA256Digest = new SHA256Digest();
    byte[] arrayOfByte8 = new byte[sHA256Digest.getDigestSize()];
    sHA256Digest.reset();
    sHA256Digest.update(arrayOfByte4, 0, arrayOfByte4.length);
    sHA256Digest.doFinal(arrayOfByte8, 0);
    this.mac.init(new KeyParameter(arrayOfByte8));
    this.mac.update(this.IV, 0, this.IV.length);
    this.mac.update(arrayOfByte1, 0, arrayOfByte1.length);
    if (arrayOfByte5 != null)
      this.mac.update(arrayOfByte5, 0, arrayOfByte5.length); 
    if (this.V.length != 0)
      this.mac.update(arrayOfByte6, 0, arrayOfByte6.length); 
    this.mac.update(this.commonMac, 0, this.commonMac.length);
    this.mac.doFinal(arrayOfByte7, 0);
    byte[] arrayOfByte9 = new byte[this.V.length + i + arrayOfByte7.length];
    System.arraycopy(this.V, 0, arrayOfByte9, 0, this.V.length);
    System.arraycopy(arrayOfByte1, 0, arrayOfByte9, this.V.length, i);
    System.arraycopy(arrayOfByte7, 0, arrayOfByte9, this.V.length + i, arrayOfByte7.length);
    return arrayOfByte9;
  }
  
  private byte[] decryptBlock(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    byte[] arrayOfByte1;
    byte[] arrayOfByte2;
    int i = 0;
    if (paramInt2 < this.V.length + this.mac.getMacSize())
      throw new InvalidCipherTextException("length of input must be greater than the MAC and V combined"); 
    if (this.cipher == null) {
      byte[] arrayOfByte9 = new byte[paramInt2 - this.V.length - this.mac.getMacSize()];
      arrayOfByte2 = new byte[this.param.getMacKeySize() / 8];
      byte[] arrayOfByte8 = new byte[arrayOfByte9.length + arrayOfByte2.length];
      this.kdf.generateBytes(arrayOfByte8, 0, arrayOfByte8.length);
      if (this.V.length != 0) {
        System.arraycopy(arrayOfByte8, 0, arrayOfByte2, 0, arrayOfByte2.length);
        System.arraycopy(arrayOfByte8, arrayOfByte2.length, arrayOfByte9, 0, arrayOfByte9.length);
      } else {
        System.arraycopy(arrayOfByte8, 0, arrayOfByte9, 0, arrayOfByte9.length);
        System.arraycopy(arrayOfByte8, arrayOfByte9.length, arrayOfByte2, 0, arrayOfByte2.length);
      } 
      arrayOfByte1 = new byte[arrayOfByte9.length];
      for (byte b = 0; b != arrayOfByte9.length; b++)
        arrayOfByte1[b] = (byte)(paramArrayOfbyte[paramInt1 + this.V.length + b] ^ arrayOfByte9[b]); 
    } else {
      ParametersWithIV parametersWithIV;
      byte[] arrayOfByte9 = new byte[((IESWithCipherParameters)this.param).getCipherKeySize() / 8];
      arrayOfByte2 = new byte[this.param.getMacKeySize() / 8];
      byte[] arrayOfByte8 = new byte[arrayOfByte9.length + arrayOfByte2.length];
      this.kdf.generateBytes(arrayOfByte8, 0, arrayOfByte8.length);
      System.arraycopy(arrayOfByte8, 0, arrayOfByte9, 0, arrayOfByte9.length);
      System.arraycopy(arrayOfByte8, arrayOfByte9.length, arrayOfByte2, 0, arrayOfByte2.length);
      KeyParameter keyParameter = new KeyParameter(arrayOfByte9);
      if (this.IV != null)
        parametersWithIV = new ParametersWithIV(keyParameter, this.IV); 
      this.cipher.init(false, parametersWithIV);
      arrayOfByte1 = new byte[this.cipher.getOutputSize(paramInt2 - this.V.length - this.mac.getMacSize())];
      i = this.cipher.processBytes(paramArrayOfbyte, paramInt1 + this.V.length, paramInt2 - this.V.length - this.mac.getMacSize(), arrayOfByte1, 0);
    } 
    byte[] arrayOfByte3 = this.param.getEncodingV();
    byte[] arrayOfByte4 = null;
    if (this.V.length != 0)
      arrayOfByte4 = getLengthTag(arrayOfByte3); 
    int j = paramInt1 + paramInt2;
    byte[] arrayOfByte5 = Arrays.copyOfRange(paramArrayOfbyte, j - this.mac.getMacSize(), j);
    byte[] arrayOfByte6 = new byte[arrayOfByte5.length];
    SHA256Digest sHA256Digest = new SHA256Digest();
    byte[] arrayOfByte7 = new byte[sHA256Digest.getDigestSize()];
    sHA256Digest.reset();
    sHA256Digest.update(arrayOfByte2, 0, arrayOfByte2.length);
    sHA256Digest.doFinal(arrayOfByte7, 0);
    this.mac.init(new KeyParameter(arrayOfByte7));
    this.mac.update(this.IV, 0, this.IV.length);
    this.mac.update(paramArrayOfbyte, paramInt1 + this.V.length, paramInt2 - this.V.length - arrayOfByte6.length);
    if (arrayOfByte3 != null)
      this.mac.update(arrayOfByte3, 0, arrayOfByte3.length); 
    if (this.V.length != 0)
      this.mac.update(arrayOfByte4, 0, arrayOfByte4.length); 
    this.mac.update(this.commonMac, 0, this.commonMac.length);
    this.mac.doFinal(arrayOfByte6, 0);
    if (!Arrays.constantTimeAreEqual(arrayOfByte5, arrayOfByte6))
      throw new InvalidCipherTextException("invalid MAC"); 
    if (this.cipher == null)
      return arrayOfByte1; 
    i += this.cipher.doFinal(arrayOfByte1, i);
    return Arrays.copyOfRange(arrayOfByte1, 0, i);
  }
  
  public byte[] processBlock(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    if (this.forEncryption) {
      if (this.keyPairGenerator != null) {
        EphemeralKeyPair ephemeralKeyPair = this.keyPairGenerator.generate();
        this.privParam = ephemeralKeyPair.getKeyPair().getPrivate();
        this.V = ephemeralKeyPair.getEncodedPublicKey();
      } 
    } else if (this.keyParser != null) {
      ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(paramArrayOfbyte, paramInt1, paramInt2);
      try {
        this.pubParam = this.keyParser.readKey(byteArrayInputStream);
      } catch (IOException iOException) {
        throw new InvalidCipherTextException("unable to recover ephemeral public key: " + iOException.getMessage(), iOException);
      } catch (IllegalArgumentException illegalArgumentException) {
        throw new InvalidCipherTextException("unable to recover ephemeral public key: " + illegalArgumentException.getMessage(), illegalArgumentException);
      } 
      int i = paramInt2 - byteArrayInputStream.available();
      this.V = Arrays.copyOfRange(paramArrayOfbyte, paramInt1, paramInt1 + i);
    } 
    this.agree.init(this.privParam);
    BigInteger bigInteger = this.agree.calculateAgreement(this.pubParam);
    byte[] arrayOfByte = BigIntegers.asUnsignedByteArray(this.agree.getFieldSize(), bigInteger);
    if (this.V.length != 0) {
      byte[] arrayOfByte1 = Arrays.concatenate(this.V, arrayOfByte);
      Arrays.fill(arrayOfByte, (byte)0);
      arrayOfByte = arrayOfByte1;
    } 
    try {
      KDFParameters kDFParameters = new KDFParameters(arrayOfByte, this.param.getDerivationV());
      this.kdf.init(kDFParameters);
      return this.forEncryption ? encryptBlock(paramArrayOfbyte, paramInt1, paramInt2) : decryptBlock(paramArrayOfbyte, paramInt1, paramInt2);
    } finally {
      Arrays.fill(arrayOfByte, (byte)0);
    } 
  }
  
  protected byte[] getLengthTag(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[8];
    if (paramArrayOfbyte != null)
      Pack.longToBigEndian(paramArrayOfbyte.length * 8L, arrayOfByte, 0); 
    return arrayOfByte;
  }
  
  public static class HandshakeKDFFunction implements DigestDerivationFunction {
    private int counterStart;
    
    private Digest digest;
    
    private byte[] shared;
    
    private byte[] iv;
    
    public HandshakeKDFFunction(int param1Int, Digest param1Digest) {
      this.counterStart = param1Int;
      this.digest = param1Digest;
    }
    
    public void init(DerivationParameters param1DerivationParameters) {
      if (param1DerivationParameters instanceof KDFParameters) {
        KDFParameters kDFParameters = (KDFParameters)param1DerivationParameters;
        this.shared = kDFParameters.getSharedSecret();
        this.iv = kDFParameters.getIV();
      } else if (param1DerivationParameters instanceof ISO18033KDFParameters) {
        ISO18033KDFParameters iSO18033KDFParameters = (ISO18033KDFParameters)param1DerivationParameters;
        this.shared = iSO18033KDFParameters.getSeed();
        this.iv = null;
      } else {
        throw new IllegalArgumentException("KDF parameters required for generator");
      } 
    }
    
    public Digest getDigest() {
      return this.digest;
    }
    
    public int generateBytes(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) throws DataLengthException, IllegalArgumentException {
      if (param1ArrayOfbyte.length - param1Int2 < param1Int1)
        throw new OutputLengthException("output buffer too small"); 
      long l = param1Int2;
      int i = this.digest.getDigestSize();
      if (l > 8589934591L)
        throw new IllegalArgumentException("output length too large"); 
      int j = (int)((l + i - 1L) / i);
      byte[] arrayOfByte1 = new byte[this.digest.getDigestSize()];
      byte[] arrayOfByte2 = new byte[4];
      Pack.intToBigEndian(this.counterStart, arrayOfByte2, 0);
      int k = this.counterStart & 0xFFFFFF00;
      for (byte b = 0; b < j; b++) {
        this.digest.update(arrayOfByte2, 0, arrayOfByte2.length);
        this.digest.update(this.shared, 0, this.shared.length);
        if (this.iv != null)
          this.digest.update(this.iv, 0, this.iv.length); 
        this.digest.doFinal(arrayOfByte1, 0);
        if (param1Int2 > i) {
          System.arraycopy(arrayOfByte1, 0, param1ArrayOfbyte, param1Int1, i);
          param1Int1 += i;
          param1Int2 -= i;
        } else {
          System.arraycopy(arrayOfByte1, 0, param1ArrayOfbyte, param1Int1, param1Int2);
        } 
        arrayOfByte2[3] = (byte)(arrayOfByte2[3] + 1);
        if ((byte)(arrayOfByte2[3] + 1) == 0) {
          k += 256;
          Pack.intToBigEndian(k, arrayOfByte2, 0);
        } 
      } 
      this.digest.reset();
      return (int)l;
    }
  }
}
