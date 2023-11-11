package org.jasypt.encryption.pbe;

import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

final class NumberUtils {
  static byte[] byteArrayFromInt(int number) {
    byte b0 = (byte)(0xFF & number);
    byte b1 = (byte)(0xFF & number >> 8);
    byte b2 = (byte)(0xFF & number >> 16);
    byte b3 = (byte)(0xFF & number >> 24);
    return new byte[] { b3, b2, b1, b0 };
  }
  
  static int intFromByteArray(byte[] byteArray) {
    if (byteArray == null || byteArray.length == 0)
      throw new IllegalArgumentException("Cannot convert an empty array into an int"); 
    int result = 0xFF & byteArray[0];
    for (int i = 1; i < byteArray.length; i++)
      result = result << 8 | 0xFF & byteArray[i]; 
    return result;
  }
  
  static byte[] processBigIntegerEncryptedByteArray(byte[] byteArray, int signum) {
    if (byteArray.length > 4) {
      int initialSize = byteArray.length;
      byte[] encryptedMessageExpectedSizeBytes = new byte[4];
      System.arraycopy(byteArray, initialSize - 4, encryptedMessageExpectedSizeBytes, 0, 4);
      byte[] processedByteArray = new byte[initialSize - 4];
      System.arraycopy(byteArray, 0, processedByteArray, 0, initialSize - 4);
      int expectedSize = intFromByteArray(encryptedMessageExpectedSizeBytes);
      if (expectedSize < 0 || expectedSize > maxSafeSizeInBytes())
        throw new EncryptionOperationNotPossibleException(); 
      if (processedByteArray.length != expectedSize) {
        int sizeDifference = expectedSize - processedByteArray.length;
        byte[] paddedProcessedByteArray = new byte[expectedSize];
        for (int i = 0; i < sizeDifference; i++)
          paddedProcessedByteArray[i] = (signum >= 0) ? 0 : -1; 
        System.arraycopy(processedByteArray, 0, paddedProcessedByteArray, sizeDifference, processedByteArray.length);
        return paddedProcessedByteArray;
      } 
      return processedByteArray;
    } 
    return (byte[])byteArray.clone();
  }
  
  private static long maxSafeSizeInBytes() {
    long max = Runtime.getRuntime().maxMemory();
    long free = Runtime.getRuntime().freeMemory();
    long total = Runtime.getRuntime().totalMemory();
    return (free + max - total) / 2L;
  }
}
