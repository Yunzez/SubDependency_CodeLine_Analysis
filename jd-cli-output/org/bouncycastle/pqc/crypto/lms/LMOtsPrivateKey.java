package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

class LMOtsPrivateKey {
  private final LMOtsParameters parameter;
  
  private final byte[] I;
  
  private final int q;
  
  private final byte[] masterSecret;
  
  public LMOtsPrivateKey(LMOtsParameters paramLMOtsParameters, byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    this.parameter = paramLMOtsParameters;
    this.I = paramArrayOfbyte1;
    this.q = paramInt;
    this.masterSecret = paramArrayOfbyte2;
  }
  
  LMSContext getSignatureContext(LMSigParameters paramLMSigParameters, byte[][] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[32];
    SeedDerive seedDerive = getDerivationFunction();
    seedDerive.setJ(-3);
    seedDerive.deriveSeed(arrayOfByte, false);
    Digest digest = DigestUtil.getDigest(this.parameter.getDigestOID());
    LmsUtils.byteArray(getI(), digest);
    LmsUtils.u32str(getQ(), digest);
    LmsUtils.u16str((short)-32383, digest);
    LmsUtils.byteArray(arrayOfByte, digest);
    return new LMSContext(this, paramLMSigParameters, digest, arrayOfByte, paramArrayOfbyte);
  }
  
  SeedDerive getDerivationFunction() {
    SeedDerive seedDerive = new SeedDerive(this.I, this.masterSecret, DigestUtil.getDigest(this.parameter.getDigestOID()));
    seedDerive.setQ(this.q);
    return seedDerive;
  }
  
  public LMOtsParameters getParameter() {
    return this.parameter;
  }
  
  public byte[] getI() {
    return this.I;
  }
  
  public int getQ() {
    return this.q;
  }
  
  public byte[] getMasterSecret() {
    return this.masterSecret;
  }
}
