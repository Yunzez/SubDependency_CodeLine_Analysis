package org.apache.commons.crypto.cipher;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public interface CryptoCipher extends Closeable {
  int getBlockSize();
  
  String getAlgorithm();
  
  void init(int paramInt, Key paramKey, AlgorithmParameterSpec paramAlgorithmParameterSpec) throws InvalidKeyException, InvalidAlgorithmParameterException;
  
  int update(ByteBuffer paramByteBuffer1, ByteBuffer paramByteBuffer2) throws ShortBufferException;
  
  int update(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws ShortBufferException;
  
  int doFinal(ByteBuffer paramByteBuffer1, ByteBuffer paramByteBuffer2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
  
  int doFinal(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
  
  default void updateAAD(byte[] aad) throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
    throw new UnsupportedOperationException();
  }
  
  default void updateAAD(ByteBuffer aad) throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
    throw new UnsupportedOperationException();
  }
}
