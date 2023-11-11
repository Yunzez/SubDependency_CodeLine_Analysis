package org.bouncycastle.pqc.crypto.lms;

public interface LMSContextBasedVerifier {
  LMSContext generateLMSContext(byte[] paramArrayOfbyte);
  
  boolean verify(LMSContext paramLMSContext);
}
