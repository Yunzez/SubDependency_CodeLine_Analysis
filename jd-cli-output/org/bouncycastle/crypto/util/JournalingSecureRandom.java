package org.bouncycastle.crypto.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Arrays;

public class JournalingSecureRandom extends SecureRandom {
  private static byte[] EMPTY_TRANSCRIPT = new byte[0];
  
  private final SecureRandom base;
  
  private TranscriptStream tOut = new TranscriptStream();
  
  private byte[] transcript;
  
  private int index = 0;
  
  public JournalingSecureRandom() {
    this(CryptoServicesRegistrar.getSecureRandom());
  }
  
  public JournalingSecureRandom(SecureRandom paramSecureRandom) {
    this.base = paramSecureRandom;
    this.transcript = EMPTY_TRANSCRIPT;
  }
  
  public JournalingSecureRandom(byte[] paramArrayOfbyte, SecureRandom paramSecureRandom) {
    this.base = paramSecureRandom;
    this.transcript = Arrays.clone(paramArrayOfbyte);
  }
  
  public final void nextBytes(byte[] paramArrayOfbyte) {
    if (this.index >= this.transcript.length) {
      this.base.nextBytes(paramArrayOfbyte);
    } else {
      byte b;
      for (b = 0; b != paramArrayOfbyte.length && this.index < this.transcript.length; b++)
        paramArrayOfbyte[b] = this.transcript[this.index++]; 
      if (b != paramArrayOfbyte.length) {
        byte[] arrayOfByte = new byte[paramArrayOfbyte.length - b];
        this.base.nextBytes(arrayOfByte);
        System.arraycopy(arrayOfByte, 0, paramArrayOfbyte, b, arrayOfByte.length);
      } 
    } 
    try {
      this.tOut.write(paramArrayOfbyte);
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to record transcript: " + iOException.getMessage());
    } 
  }
  
  public void clear() {
    Arrays.fill(this.transcript, (byte)0);
    this.tOut.clear();
  }
  
  public void reset() {
    this.index = 0;
    if (this.index == this.transcript.length)
      this.transcript = this.tOut.toByteArray(); 
    this.tOut.reset();
  }
  
  public byte[] getTranscript() {
    return this.tOut.toByteArray();
  }
  
  public byte[] getFullTranscript() {
    return (this.index == this.transcript.length) ? this.tOut.toByteArray() : Arrays.clone(this.transcript);
  }
  
  private class TranscriptStream extends ByteArrayOutputStream {
    private TranscriptStream() {}
    
    public void clear() {
      Arrays.fill(this.buf, (byte)0);
    }
  }
}
