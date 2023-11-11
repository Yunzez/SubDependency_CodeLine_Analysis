package org.jasypt.iv;

public interface IvGenerator {
  byte[] generateIv(int paramInt);
  
  boolean includePlainIvInEncryptionResults();
}
