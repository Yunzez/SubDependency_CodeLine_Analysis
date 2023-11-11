package org.bouncycastle.crypto;

public interface AlphabetMapper {
  int getRadix();
  
  byte[] convertToIndexes(char[] paramArrayOfchar);
  
  char[] convertToChars(byte[] paramArrayOfbyte);
}
