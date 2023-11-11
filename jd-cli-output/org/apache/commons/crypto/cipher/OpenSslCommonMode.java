package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class OpenSslCommonMode extends OpenSslFeedbackCipher {
  OpenSslCommonMode(long context, int algorithmMode, int padding) {
    super(context, algorithmMode, padding);
  }
  
  public void init(int mode, byte[] key, AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    byte[] iv;
    this.cipherMode = mode;
    if (params instanceof IvParameterSpec) {
      iv = ((IvParameterSpec)params).getIV();
    } else {
      throw new InvalidAlgorithmParameterException("Illegal parameters");
    } 
    this.context = OpenSslNative.init(this.context, mode, this.algorithmMode, this.padding, key, iv);
  }
  
  public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
    checkState();
    int len = OpenSslNative.update(this.context, input, input.position(), input
        .remaining(), output, output.position(), output
        .remaining());
    input.position(input.limit());
    output.position(output.position() + len);
    return len;
  }
  
  public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    checkState();
    return OpenSslNative.updateByteArray(this.context, input, inputOffset, inputLen, output, outputOffset, output.length - outputOffset);
  }
  
  public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    checkState();
    int len = OpenSslNative.updateByteArray(this.context, input, inputOffset, inputLen, output, outputOffset, output.length - outputOffset);
    len += OpenSslNative.doFinalByteArray(this.context, output, outputOffset + len, output.length - outputOffset - len);
    return len;
  }
  
  public int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    checkState();
    int totalLen = 0;
    int len = OpenSslNative.update(this.context, input, input.position(), input
        .remaining(), output, output.position(), output.remaining());
    totalLen += len;
    input.position(input.limit());
    output.position(output.position() + len);
    len = OpenSslNative.doFinal(this.context, output, output.position(), output
        .remaining());
    totalLen += len;
    output.position(output.position() + len);
    return totalLen;
  }
  
  public void updateAAD(byte[] aad) {
    throw new UnsupportedOperationException("The underlying Cipher implementation does not support this method");
  }
}
