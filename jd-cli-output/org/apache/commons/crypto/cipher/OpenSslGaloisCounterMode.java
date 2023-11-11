package org.apache.commons.crypto.cipher;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;

class OpenSslGaloisCounterMode extends OpenSslFeedbackCipher {
  private ByteArrayOutputStream aadBuffer = new ByteArrayOutputStream();
  
  private int tagBitLen = -1;
  
  static final int DEFAULT_TAG_LEN = 16;
  
  private ByteArrayOutputStream inBuffer = null;
  
  public OpenSslGaloisCounterMode(long context, int algorithmMode, int padding) {
    super(context, algorithmMode, padding);
  }
  
  public void init(int mode, byte[] key, AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    byte[] iv;
    if (this.aadBuffer == null) {
      this.aadBuffer = new ByteArrayOutputStream();
    } else {
      this.aadBuffer.reset();
    } 
    this.cipherMode = mode;
    if (params instanceof GCMParameterSpec) {
      GCMParameterSpec gcmParam = (GCMParameterSpec)params;
      iv = gcmParam.getIV();
      this.tagBitLen = gcmParam.getTLen();
    } else {
      throw new InvalidAlgorithmParameterException("Illegal parameters");
    } 
    if (this.cipherMode == 0)
      this.inBuffer = new ByteArrayOutputStream(); 
    this.context = OpenSslNative.init(this.context, mode, this.algorithmMode, this.padding, key, iv);
  }
  
  public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
    checkState();
    processAAD();
    if (this.cipherMode == 0) {
      int inputLen = input.remaining();
      byte[] inputBuf = new byte[inputLen];
      input.get(inputBuf, 0, inputLen);
      this.inBuffer.write(inputBuf, 0, inputLen);
      return 0;
    } 
    int len = OpenSslNative.update(this.context, input, input.position(), input
        .remaining(), output, output.position(), output
        .remaining());
    input.position(input.limit());
    output.position(output.position() + len);
    return len;
  }
  
  public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
    checkState();
    processAAD();
    if (this.cipherMode == 0) {
      this.inBuffer.write(input, inputOffset, inputLen);
      return 0;
    } 
    return OpenSslNative.updateByteArray(this.context, input, inputOffset, inputLen, output, outputOffset, output.length - outputOffset);
  }
  
  public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    int len;
    checkState();
    processAAD();
    if (this.cipherMode == 0) {
      byte[] inputFinal;
      int inputOffsetFinal = inputOffset;
      int inputLenFinal = inputLen;
      if (this.inBuffer != null && this.inBuffer.size() > 0) {
        this.inBuffer.write(input, inputOffset, inputLen);
        inputFinal = this.inBuffer.toByteArray();
        inputOffsetFinal = 0;
        inputLenFinal = inputFinal.length;
        this.inBuffer.reset();
      } else {
        inputFinal = input;
      } 
      if (inputFinal.length < getTagLen())
        throw new AEADBadTagException("Input too short - need tag"); 
      int inputDataLen = inputLenFinal - getTagLen();
      len = OpenSslNative.updateByteArray(this.context, inputFinal, inputOffsetFinal, inputDataLen, output, outputOffset, output.length - outputOffset);
      ByteBuffer tag = ByteBuffer.allocate(getTagLen());
      tag.put(input, input.length - getTagLen(), getTagLen());
      tag.flip();
      evpCipherCtxCtrl(this.context, OpenSslEvpCtrlValues.AEAD_SET_TAG.getValue(), getTagLen(), tag);
    } else {
      len = OpenSslNative.updateByteArray(this.context, input, inputOffset, inputLen, output, outputOffset, output.length - outputOffset);
    } 
    len += OpenSslNative.doFinalByteArray(this.context, output, outputOffset + len, output.length - outputOffset - len);
    if (this.cipherMode == 1) {
      ByteBuffer tag = ByteBuffer.allocate(getTagLen());
      evpCipherCtxCtrl(this.context, OpenSslEvpCtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
      tag.get(output, output.length - getTagLen(), getTagLen());
      len += getTagLen();
    } 
    return len;
  }
  
  public int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    checkState();
    processAAD();
    int totalLen = 0;
    if (this.cipherMode == 0) {
      ByteBuffer tag = ByteBuffer.allocate(getTagLen());
      if (this.inBuffer != null && this.inBuffer.size() > 0) {
        byte[] inputBytes = new byte[input.remaining()];
        input.get(inputBytes, 0, inputBytes.length);
        this.inBuffer.write(inputBytes, 0, inputBytes.length);
        byte[] inputFinal = this.inBuffer.toByteArray();
        this.inBuffer.reset();
        if (inputFinal.length < getTagLen())
          throw new AEADBadTagException("Input too short - need tag"); 
        len = OpenSslNative.updateByteArrayByteBuffer(this.context, inputFinal, 0, inputFinal.length - 
            getTagLen(), output, output
            .position(), output.remaining());
        tag.put(inputFinal, inputFinal.length - getTagLen(), getTagLen());
        tag.flip();
      } else {
        if (input.remaining() < getTagLen())
          throw new AEADBadTagException("Input too short - need tag"); 
        len = OpenSslNative.update(this.context, input, input.position(), input
            .remaining() - getTagLen(), output, output.position(), output
            .remaining());
        input.position(input.position() + len);
        tag.put(input);
        tag.flip();
      } 
      evpCipherCtxCtrl(this.context, OpenSslEvpCtrlValues.AEAD_SET_TAG.getValue(), 
          getTagLen(), tag);
    } else {
      len = OpenSslNative.update(this.context, input, input.position(), input
          .remaining(), output, output.position(), output
          .remaining());
      input.position(input.limit());
    } 
    totalLen += len;
    output.position(output.position() + len);
    int len = OpenSslNative.doFinal(this.context, output, output.position(), output
        .remaining());
    output.position(output.position() + len);
    totalLen += len;
    if (this.cipherMode == 1) {
      ByteBuffer tag = ByteBuffer.allocate(getTagLen());
      evpCipherCtxCtrl(this.context, OpenSslEvpCtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
      output.put(tag);
      totalLen += getTagLen();
    } 
    return totalLen;
  }
  
  public void clean() {
    super.clean();
    this.aadBuffer = null;
  }
  
  public void updateAAD(byte[] aad) {
    if (this.aadBuffer != null) {
      this.aadBuffer.write(aad, 0, aad.length);
    } else {
      throw new IllegalStateException("Update has been called; no more AAD data");
    } 
  }
  
  private void processAAD() {
    if (this.aadBuffer != null && this.aadBuffer.size() > 0) {
      OpenSslNative.updateByteArray(this.context, this.aadBuffer.toByteArray(), 0, this.aadBuffer
          .size(), null, 0, 0);
      this.aadBuffer = null;
    } 
  }
  
  private int getTagLen() {
    return (this.tagBitLen < 0) ? 16 : (this.tagBitLen >> 3);
  }
  
  private void evpCipherCtxCtrl(long context, int type, int arg, ByteBuffer bb) {
    checkState();
    try {
      if (bb != null) {
        bb.order(ByteOrder.nativeOrder());
        OpenSslNative.ctrl(context, type, arg, bb.array());
      } else {
        OpenSslNative.ctrl(context, type, arg, null);
      } 
    } catch (Exception e) {
      System.out.println(e.getMessage());
    } 
  }
}
