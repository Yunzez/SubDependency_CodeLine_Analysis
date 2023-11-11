package org.apache.commons.crypto.random;

import java.io.Closeable;

public interface CryptoRandom extends Closeable {
  void nextBytes(byte[] paramArrayOfbyte);
}
