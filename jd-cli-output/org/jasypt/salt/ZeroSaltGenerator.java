package org.jasypt.salt;

import java.util.Arrays;

public class ZeroSaltGenerator implements SaltGenerator {
  public byte[] generateSalt(int lengthBytes) {
    byte[] result = new byte[lengthBytes];
    Arrays.fill(result, (byte)0);
    return result;
  }
  
  public boolean includePlainSaltInEncryptionResults() {
    return false;
  }
}
