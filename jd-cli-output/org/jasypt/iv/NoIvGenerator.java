package org.jasypt.iv;

public class NoIvGenerator implements IvGenerator {
  public byte[] generateIv(int lengthBytes) {
    return new byte[0];
  }
  
  public boolean includePlainIvInEncryptionResults() {
    return false;
  }
}
