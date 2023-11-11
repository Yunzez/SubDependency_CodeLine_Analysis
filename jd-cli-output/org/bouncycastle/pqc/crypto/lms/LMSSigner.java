package org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class LMSSigner implements MessageSigner {
  private LMSPrivateKeyParameters privKey;
  
  private LMSPublicKeyParameters pubKey;
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    if (paramBoolean) {
      this.privKey = (LMSPrivateKeyParameters)paramCipherParameters;
    } else {
      this.pubKey = (LMSPublicKeyParameters)paramCipherParameters;
    } 
  }
  
  public byte[] generateSignature(byte[] paramArrayOfbyte) {
    try {
      return LMS.generateSign(this.privKey, paramArrayOfbyte).getEncoded();
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to encode signature: " + iOException.getMessage());
    } 
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    try {
      return LMS.verifySignature(this.pubKey, LMSSignature.getInstance(paramArrayOfbyte2), paramArrayOfbyte1);
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to decode signature: " + iOException.getMessage());
    } 
  }
}
