package org.jasypt.digest;

public interface ByteDigester {
  byte[] digest(byte[] paramArrayOfbyte);
  
  boolean matches(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2);
}
