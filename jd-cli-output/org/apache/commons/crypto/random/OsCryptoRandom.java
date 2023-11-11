package org.apache.commons.crypto.random;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Random;
import org.apache.commons.crypto.utils.IoUtils;

class OsCryptoRandom extends Random implements CryptoRandom {
  private static final long serialVersionUID = 6391500337172057900L;
  
  private static final int RESERVOIR_LENGTH = 8192;
  
  private transient FileInputStream stream;
  
  private final byte[] reservoir = new byte[8192];
  
  private int pos = this.reservoir.length;
  
  private void fillReservoir(int min) {
    if (this.pos >= this.reservoir.length - min) {
      try {
        IoUtils.readFully(this.stream, this.reservoir, 0, this.reservoir.length);
      } catch (IOException e) {
        throw new IllegalStateException("failed to fill reservoir", e);
      } 
      this.pos = 0;
    } 
  }
  
  public OsCryptoRandom(Properties props) {
    File randomDevFile = new File(props.getProperty("commons.crypto.secure.random.device.file.path", "/dev/urandom"));
    try {
      close();
      this.stream = new FileInputStream(randomDevFile);
    } catch (IOException e) {
      throw new IllegalArgumentException(e);
    } 
    try {
      fillReservoir(0);
    } catch (IllegalStateException e) {
      close();
      throw e;
    } 
  }
  
  public synchronized void nextBytes(byte[] bytes) {
    int off = 0;
    int n = 0;
    while (off < bytes.length) {
      fillReservoir(0);
      n = Math.min(bytes.length - off, this.reservoir.length - this.pos);
      System.arraycopy(this.reservoir, this.pos, bytes, off, n);
      off += n;
      this.pos += n;
    } 
  }
  
  protected synchronized int next(int nbits) {
    fillReservoir(4);
    int n = 0;
    for (int i = 0; i < 4; i++)
      n = n << 8 | this.reservoir[this.pos++] & 0xFF; 
    return n & -1 >> 32 - nbits;
  }
  
  public synchronized void close() {
    if (this.stream != null) {
      IoUtils.closeQuietly(this.stream);
      this.stream = null;
    } 
  }
}
