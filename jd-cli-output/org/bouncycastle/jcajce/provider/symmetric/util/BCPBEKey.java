package org.bouncycastle.jcajce.provider.symmetric.util;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Destroyable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class BCPBEKey implements PBEKey, Destroyable {
  private final AtomicBoolean hasBeenDestroyed = new AtomicBoolean(false);
  
  String algorithm;
  
  ASN1ObjectIdentifier oid;
  
  int type;
  
  int digest;
  
  int keySize;
  
  int ivSize;
  
  private final char[] password;
  
  private final byte[] salt;
  
  private final int iterationCount;
  
  private final CipherParameters param;
  
  boolean tryWrong = false;
  
  public BCPBEKey(String paramString, ASN1ObjectIdentifier paramASN1ObjectIdentifier, int paramInt1, int paramInt2, int paramInt3, int paramInt4, PBEKeySpec paramPBEKeySpec, CipherParameters paramCipherParameters) {
    this.algorithm = paramString;
    this.oid = paramASN1ObjectIdentifier;
    this.type = paramInt1;
    this.digest = paramInt2;
    this.keySize = paramInt3;
    this.ivSize = paramInt4;
    this.password = paramPBEKeySpec.getPassword();
    this.iterationCount = paramPBEKeySpec.getIterationCount();
    this.salt = paramPBEKeySpec.getSalt();
    this.param = paramCipherParameters;
  }
  
  public BCPBEKey(String paramString, CipherParameters paramCipherParameters) {
    this.algorithm = paramString;
    this.param = paramCipherParameters;
    this.password = null;
    this.iterationCount = -1;
    this.salt = null;
  }
  
  public String getAlgorithm() {
    checkDestroyed(this);
    return this.algorithm;
  }
  
  public String getFormat() {
    return "RAW";
  }
  
  public byte[] getEncoded() {
    checkDestroyed(this);
    if (this.param != null) {
      KeyParameter keyParameter;
      if (this.param instanceof ParametersWithIV) {
        keyParameter = (KeyParameter)((ParametersWithIV)this.param).getParameters();
      } else {
        keyParameter = (KeyParameter)this.param;
      } 
      return keyParameter.getKey();
    } 
    return (this.type == 2) ? PBEParametersGenerator.PKCS12PasswordToBytes(this.password) : ((this.type == 5) ? PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(this.password) : PBEParametersGenerator.PKCS5PasswordToBytes(this.password));
  }
  
  int getType() {
    checkDestroyed(this);
    return this.type;
  }
  
  int getDigest() {
    checkDestroyed(this);
    return this.digest;
  }
  
  int getKeySize() {
    checkDestroyed(this);
    return this.keySize;
  }
  
  public int getIvSize() {
    checkDestroyed(this);
    return this.ivSize;
  }
  
  public CipherParameters getParam() {
    checkDestroyed(this);
    return this.param;
  }
  
  public char[] getPassword() {
    checkDestroyed(this);
    if (this.password == null)
      throw new IllegalStateException("no password available"); 
    return Arrays.clone(this.password);
  }
  
  public byte[] getSalt() {
    checkDestroyed(this);
    return Arrays.clone(this.salt);
  }
  
  public int getIterationCount() {
    checkDestroyed(this);
    return this.iterationCount;
  }
  
  public ASN1ObjectIdentifier getOID() {
    checkDestroyed(this);
    return this.oid;
  }
  
  public void setTryWrongPKCS12Zero(boolean paramBoolean) {
    this.tryWrong = paramBoolean;
  }
  
  boolean shouldTryWrongPKCS12() {
    return this.tryWrong;
  }
  
  public void destroy() {
    if (!this.hasBeenDestroyed.getAndSet(true)) {
      if (this.password != null)
        Arrays.fill(this.password, false); 
      if (this.salt != null)
        Arrays.fill(this.salt, (byte)0); 
    } 
  }
  
  public boolean isDestroyed() {
    return this.hasBeenDestroyed.get();
  }
  
  static void checkDestroyed(Destroyable paramDestroyable) {
    if (paramDestroyable.isDestroyed())
      throw new IllegalStateException("key has been destroyed"); 
  }
}
