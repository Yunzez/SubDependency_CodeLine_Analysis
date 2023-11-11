package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.pqc.crypto.lms.LMSContext;

public interface LMSContextBasedVerifier {
  LMSContext generateLMSContext(byte[] paramArrayOfbyte);
  
  boolean verify(LMSContext paramLMSContext);
}
