package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import org.apache.commons.crypto.utils.Utils;

abstract class OpenSslFeedbackCipher {
  protected long context = 0L;
  
  protected final int algorithmMode;
  
  protected final int padding;
  
  protected int cipherMode = 0;
  
  OpenSslFeedbackCipher(long context, int algorithmMode, int padding) {
    this.context = context;
    this.algorithmMode = algorithmMode;
    this.padding = padding;
  }
  
  abstract void init(int paramInt, byte[] paramArrayOfbyte, AlgorithmParameterSpec paramAlgorithmParameterSpec) throws InvalidAlgorithmParameterException;
  
  abstract int update(ByteBuffer paramByteBuffer1, ByteBuffer paramByteBuffer2) throws ShortBufferException;
  
  abstract int update(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws ShortBufferException;
  
  abstract int doFinal(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
  
  abstract int doFinal(ByteBuffer paramByteBuffer1, ByteBuffer paramByteBuffer2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
  
  abstract void updateAAD(byte[] paramArrayOfbyte);
  
  public void clean() {
    if (this.context != 0L) {
      OpenSslNative.clean(this.context);
      this.context = 0L;
    } 
  }
  
  public void checkState() {
    Utils.checkState((this.context != 0L), "Cipher context is invalid.");
  }
}
