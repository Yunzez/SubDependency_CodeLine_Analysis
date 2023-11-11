package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CharToByteConverter;
import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.util.Arrays;

public class Argon2Parameters {
  public static final int ARGON2_d = 0;
  
  public static final int ARGON2_i = 1;
  
  public static final int ARGON2_id = 2;
  
  public static final int ARGON2_VERSION_10 = 16;
  
  public static final int ARGON2_VERSION_13 = 19;
  
  private static final int DEFAULT_ITERATIONS = 3;
  
  private static final int DEFAULT_MEMORY_COST = 12;
  
  private static final int DEFAULT_LANES = 1;
  
  private static final int DEFAULT_TYPE = 1;
  
  private static final int DEFAULT_VERSION = 19;
  
  private final byte[] salt;
  
  private final byte[] secret;
  
  private final byte[] additional;
  
  private final int iterations;
  
  private final int memory;
  
  private final int lanes;
  
  private final int version;
  
  private final int type;
  
  private final CharToByteConverter converter;
  
  private Argon2Parameters(int paramInt1, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, int paramInt2, int paramInt3, int paramInt4, int paramInt5, CharToByteConverter paramCharToByteConverter) {
    this.salt = Arrays.clone(paramArrayOfbyte1);
    this.secret = Arrays.clone(paramArrayOfbyte2);
    this.additional = Arrays.clone(paramArrayOfbyte3);
    this.iterations = paramInt2;
    this.memory = paramInt3;
    this.lanes = paramInt4;
    this.version = paramInt5;
    this.type = paramInt1;
    this.converter = paramCharToByteConverter;
  }
  
  public byte[] getSalt() {
    return Arrays.clone(this.salt);
  }
  
  public byte[] getSecret() {
    return Arrays.clone(this.secret);
  }
  
  public byte[] getAdditional() {
    return Arrays.clone(this.additional);
  }
  
  public int getIterations() {
    return this.iterations;
  }
  
  public int getMemory() {
    return this.memory;
  }
  
  public int getLanes() {
    return this.lanes;
  }
  
  public int getVersion() {
    return this.version;
  }
  
  public int getType() {
    return this.type;
  }
  
  public CharToByteConverter getCharToByteConverter() {
    return this.converter;
  }
  
  public void clear() {
    Arrays.clear(this.salt);
    Arrays.clear(this.secret);
    Arrays.clear(this.additional);
  }
  
  public static class Builder {
    private byte[] salt;
    
    private byte[] secret;
    
    private byte[] additional;
    
    private int iterations;
    
    private int memory;
    
    private int lanes;
    
    private int version;
    
    private final int type;
    
    private CharToByteConverter converter = PasswordConverter.UTF8;
    
    public Builder() {
      this(1);
    }
    
    public Builder(int param1Int) {
      this.type = param1Int;
      this.lanes = 1;
      this.memory = 4096;
      this.iterations = 3;
      this.version = 19;
    }
    
    public Builder withParallelism(int param1Int) {
      this.lanes = param1Int;
      return this;
    }
    
    public Builder withSalt(byte[] param1ArrayOfbyte) {
      this.salt = Arrays.clone(param1ArrayOfbyte);
      return this;
    }
    
    public Builder withSecret(byte[] param1ArrayOfbyte) {
      this.secret = Arrays.clone(param1ArrayOfbyte);
      return this;
    }
    
    public Builder withAdditional(byte[] param1ArrayOfbyte) {
      this.additional = Arrays.clone(param1ArrayOfbyte);
      return this;
    }
    
    public Builder withIterations(int param1Int) {
      this.iterations = param1Int;
      return this;
    }
    
    public Builder withMemoryAsKB(int param1Int) {
      this.memory = param1Int;
      return this;
    }
    
    public Builder withMemoryPowOfTwo(int param1Int) {
      this.memory = 1 << param1Int;
      return this;
    }
    
    public Builder withVersion(int param1Int) {
      this.version = param1Int;
      return this;
    }
    
    public Builder withCharToByteConverter(CharToByteConverter param1CharToByteConverter) {
      this.converter = param1CharToByteConverter;
      return this;
    }
    
    public Argon2Parameters build() {
      return new Argon2Parameters(this.type, this.salt, this.secret, this.additional, this.iterations, this.memory, this.lanes, this.version, this.converter);
    }
    
    public void clear() {
      Arrays.clear(this.salt);
      Arrays.clear(this.secret);
      Arrays.clear(this.additional);
    }
  }
}
