package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.lms.LMOtsPrivateKey;
import org.bouncycastle.pqc.crypto.lms.LMOtsPublicKey;
import org.bouncycastle.pqc.crypto.lms.LMSSignedPubKey;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

public class LMSContext implements Digest {
  private final byte[] C;
  
  private final LMOtsPrivateKey key;
  
  private final LMSigParameters sigParams;
  
  private final byte[][] path;
  
  private final LMOtsPublicKey publicKey;
  
  private final Object signature;
  
  private LMSSignedPubKey[] signedPubKeys;
  
  private volatile Digest digest;
  
  public LMSContext(LMOtsPrivateKey paramLMOtsPrivateKey, LMSigParameters paramLMSigParameters, Digest paramDigest, byte[] paramArrayOfbyte, byte[][] paramArrayOfbyte1) {
    this.key = paramLMOtsPrivateKey;
    this.sigParams = paramLMSigParameters;
    this.digest = paramDigest;
    this.C = paramArrayOfbyte;
    this.path = paramArrayOfbyte1;
    this.publicKey = null;
    this.signature = null;
  }
  
  public LMSContext(LMOtsPublicKey paramLMOtsPublicKey, Object paramObject, Digest paramDigest) {
    this.publicKey = paramLMOtsPublicKey;
    this.signature = paramObject;
    this.digest = paramDigest;
    this.C = null;
    this.key = null;
    this.sigParams = null;
    this.path = null;
  }
  
  byte[] getC() {
    return this.C;
  }
  
  byte[] getQ() {
    byte[] arrayOfByte = new byte[34];
    this.digest.doFinal(arrayOfByte, 0);
    this.digest = null;
    return arrayOfByte;
  }
  
  byte[][] getPath() {
    return this.path;
  }
  
  LMOtsPrivateKey getPrivateKey() {
    return this.key;
  }
  
  public LMOtsPublicKey getPublicKey() {
    return this.publicKey;
  }
  
  LMSigParameters getSigParams() {
    return this.sigParams;
  }
  
  public Object getSignature() {
    return this.signature;
  }
  
  LMSSignedPubKey[] getSignedPubKeys() {
    return this.signedPubKeys;
  }
  
  org.bouncycastle.pqc.crypto.lms.LMSContext withSignedPublicKeys(LMSSignedPubKey[] paramArrayOfLMSSignedPubKey) {
    this.signedPubKeys = paramArrayOfLMSSignedPubKey;
    return this;
  }
  
  public String getAlgorithmName() {
    return this.digest.getAlgorithmName();
  }
  
  public int getDigestSize() {
    return this.digest.getDigestSize();
  }
  
  public void update(byte paramByte) {
    this.digest.update(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    return this.digest.doFinal(paramArrayOfbyte, paramInt);
  }
  
  public void reset() {
    this.digest.reset();
  }
}
