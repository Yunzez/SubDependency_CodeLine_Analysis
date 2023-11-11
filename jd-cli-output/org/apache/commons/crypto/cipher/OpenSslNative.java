package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;

class OpenSslNative {
  public static native void initIDs();
  
  public static native long initContext(int paramInt1, int paramInt2);
  
  public static native long init(long paramLong, int paramInt1, int paramInt2, int paramInt3, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2);
  
  public static native int update(long paramLong, ByteBuffer paramByteBuffer1, int paramInt1, int paramInt2, ByteBuffer paramByteBuffer2, int paramInt3, int paramInt4);
  
  public static native int updateByteArray(long paramLong, byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4);
  
  public static native int updateByteArrayByteBuffer(long paramLong, byte[] paramArrayOfbyte, int paramInt1, int paramInt2, ByteBuffer paramByteBuffer, int paramInt3, int paramInt4);
  
  public static native int doFinal(long paramLong, ByteBuffer paramByteBuffer, int paramInt1, int paramInt2);
  
  public static native int doFinalByteArray(long paramLong, byte[] paramArrayOfbyte, int paramInt1, int paramInt2);
  
  public static native int ctrl(long paramLong, int paramInt1, int paramInt2, byte[] paramArrayOfbyte);
  
  public static native void clean(long paramLong);
}
