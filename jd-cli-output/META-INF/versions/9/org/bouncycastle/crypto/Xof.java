package META-INF.versions.9.org.bouncycastle.crypto;

import org.bouncycastle.crypto.ExtendedDigest;

public interface Xof extends ExtendedDigest {
  int doFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2);
  
  int doOutput(byte[] paramArrayOfbyte, int paramInt1, int paramInt2);
}
