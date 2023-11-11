package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

public class Argon2BytesGenerator {
  private static final int ARGON2_BLOCK_SIZE = 1024;
  
  private static final int ARGON2_QWORDS_IN_BLOCK = 128;
  
  private static final int ARGON2_ADDRESSES_IN_BLOCK = 128;
  
  private static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;
  
  private static final int ARGON2_PREHASH_SEED_LENGTH = 72;
  
  private static final int ARGON2_SYNC_POINTS = 4;
  
  private static final int MIN_PARALLELISM = 1;
  
  private static final int MAX_PARALLELISM = 16777216;
  
  private static final int MIN_OUTLEN = 4;
  
  private static final int MIN_ITERATIONS = 1;
  
  private static final long M32L = 4294967295L;
  
  private static final byte[] ZERO_BYTES = new byte[4];
  
  private Argon2Parameters parameters;
  
  private Block[] memory;
  
  private int segmentLength;
  
  private int laneLength;
  
  public void init(Argon2Parameters paramArgon2Parameters) {
    this.parameters = paramArgon2Parameters;
    if (paramArgon2Parameters.getLanes() < 1)
      throw new IllegalStateException("lanes must be greater than 1"); 
    if (paramArgon2Parameters.getLanes() > 16777216)
      throw new IllegalStateException("lanes must be less than 16777216"); 
    if (paramArgon2Parameters.getMemory() < 2 * paramArgon2Parameters.getLanes())
      throw new IllegalStateException("memory is less than: " + (2 * paramArgon2Parameters.getLanes()) + " expected " + (2 * paramArgon2Parameters.getLanes())); 
    if (paramArgon2Parameters.getIterations() < 1)
      throw new IllegalStateException("iterations is less than: 1"); 
    doInit(paramArgon2Parameters);
  }
  
  public int generateBytes(char[] paramArrayOfchar, byte[] paramArrayOfbyte) {
    return generateBytes(this.parameters.getCharToByteConverter().convert(paramArrayOfchar), paramArrayOfbyte);
  }
  
  public int generateBytes(char[] paramArrayOfchar, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    return generateBytes(this.parameters.getCharToByteConverter().convert(paramArrayOfchar), paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int generateBytes(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    return generateBytes(paramArrayOfbyte1, paramArrayOfbyte2, 0, paramArrayOfbyte2.length);
  }
  
  public int generateBytes(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2) {
    if (paramInt2 < 4)
      throw new IllegalStateException("output length less than 4"); 
    byte[] arrayOfByte = new byte[1024];
    initialize(arrayOfByte, paramArrayOfbyte1, paramInt2);
    fillMemoryBlocks();
    digest(arrayOfByte, paramArrayOfbyte2, paramInt1, paramInt2);
    reset();
    return paramInt2;
  }
  
  private void reset() {
    if (null != this.memory)
      for (byte b = 0; b < this.memory.length; b++) {
        Block block = this.memory[b];
        if (null != block)
          block.clear(); 
      }  
  }
  
  private void doInit(Argon2Parameters paramArgon2Parameters) {
    int i = paramArgon2Parameters.getMemory();
    if (i < 8 * paramArgon2Parameters.getLanes())
      i = 8 * paramArgon2Parameters.getLanes(); 
    this.segmentLength = i / paramArgon2Parameters.getLanes() * 4;
    this.laneLength = this.segmentLength * 4;
    i = this.segmentLength * paramArgon2Parameters.getLanes() * 4;
    initMemory(i);
  }
  
  private void initMemory(int paramInt) {
    this.memory = new Block[paramInt];
    for (byte b = 0; b < this.memory.length; b++)
      this.memory[b] = new Block(); 
  }
  
  private void fillMemoryBlocks() {
    FillBlock fillBlock = new FillBlock();
    Position position = new Position();
    for (byte b = 0; b < this.parameters.getIterations(); b++) {
      position.pass = b;
      for (byte b1 = 0; b1 < 4; b1++) {
        position.slice = b1;
        for (byte b2 = 0; b2 < this.parameters.getLanes(); b2++) {
          position.lane = b2;
          fillSegment(fillBlock, position);
        } 
      } 
    } 
  }
  
  private void fillSegment(FillBlock paramFillBlock, Position paramPosition) {
    Block block1 = null;
    Block block2 = null;
    boolean bool1 = isDataIndependentAddressing(paramPosition);
    int i = getStartingIndex(paramPosition);
    int j = paramPosition.lane * this.laneLength + paramPosition.slice * this.segmentLength + i;
    int k = getPrevOffset(j);
    if (bool1) {
      block1 = paramFillBlock.addressBlock.clear();
      block2 = paramFillBlock.inputBlock.clear();
      initAddressBlocks(paramFillBlock, paramPosition, block2, block1);
    } 
    boolean bool2 = isWithXor(paramPosition);
    for (int m = i; m < this.segmentLength; m++) {
      long l = getPseudoRandom(paramFillBlock, m, block1, block2, k, bool1);
      int n = getRefLane(paramPosition, l);
      int i1 = getRefColumn(paramPosition, m, l, (n == paramPosition.lane));
      Block block3 = this.memory[k];
      Block block4 = this.memory[this.laneLength * n + i1];
      Block block5 = this.memory[j];
      if (bool2) {
        paramFillBlock.fillBlockWithXor(block3, block4, block5);
      } else {
        paramFillBlock.fillBlock(block3, block4, block5);
      } 
      k = j;
      j++;
    } 
  }
  
  private boolean isDataIndependentAddressing(Position paramPosition) {
    return (this.parameters.getType() == 1 || (this.parameters.getType() == 2 && paramPosition.pass == 0 && paramPosition.slice < 2));
  }
  
  private void initAddressBlocks(FillBlock paramFillBlock, Position paramPosition, Block paramBlock1, Block paramBlock2) {
    paramBlock1.v[0] = intToLong(paramPosition.pass);
    paramBlock1.v[1] = intToLong(paramPosition.lane);
    paramBlock1.v[2] = intToLong(paramPosition.slice);
    paramBlock1.v[3] = intToLong(this.memory.length);
    paramBlock1.v[4] = intToLong(this.parameters.getIterations());
    paramBlock1.v[5] = intToLong(this.parameters.getType());
    if (paramPosition.pass == 0 && paramPosition.slice == 0)
      nextAddresses(paramFillBlock, paramBlock1, paramBlock2); 
  }
  
  private boolean isWithXor(Position paramPosition) {
    return (paramPosition.pass != 0 && this.parameters.getVersion() != 16);
  }
  
  private int getPrevOffset(int paramInt) {
    return (paramInt % this.laneLength == 0) ? (paramInt + this.laneLength - 1) : (paramInt - 1);
  }
  
  private static int getStartingIndex(Position paramPosition) {
    return (paramPosition.pass == 0 && paramPosition.slice == 0) ? 2 : 0;
  }
  
  private void nextAddresses(FillBlock paramFillBlock, Block paramBlock1, Block paramBlock2) {
    paramBlock1.v[6] = paramBlock1.v[6] + 1L;
    paramFillBlock.fillBlock(paramBlock1, paramBlock2);
    paramFillBlock.fillBlock(paramBlock2, paramBlock2);
  }
  
  private long getPseudoRandom(FillBlock paramFillBlock, int paramInt1, Block paramBlock1, Block paramBlock2, int paramInt2, boolean paramBoolean) {
    if (paramBoolean) {
      int i = paramInt1 % 128;
      if (i == 0)
        nextAddresses(paramFillBlock, paramBlock2, paramBlock1); 
      return paramBlock1.v[i];
    } 
    return (this.memory[paramInt2]).v[0];
  }
  
  private int getRefLane(Position paramPosition, long paramLong) {
    int i = (int)((paramLong >>> 32L) % this.parameters.getLanes());
    if (paramPosition.pass == 0 && paramPosition.slice == 0)
      i = paramPosition.lane; 
    return i;
  }
  
  private int getRefColumn(Position paramPosition, int paramInt, long paramLong, boolean paramBoolean) {
    int i;
    int j;
    if (paramPosition.pass == 0) {
      j = 0;
      if (paramBoolean) {
        i = paramPosition.slice * this.segmentLength + paramInt - 1;
      } else {
        i = paramPosition.slice * this.segmentLength + ((paramInt == 0) ? -1 : 0);
      } 
    } else {
      j = (paramPosition.slice + 1) * this.segmentLength % this.laneLength;
      if (paramBoolean) {
        i = this.laneLength - this.segmentLength + paramInt - 1;
      } else {
        i = this.laneLength - this.segmentLength + ((paramInt == 0) ? -1 : 0);
      } 
    } 
    long l = paramLong & 0xFFFFFFFFL;
    l = l * l >>> 32L;
    l = (i - 1) - (i * l >>> 32L);
    return (int)(j + l) % this.laneLength;
  }
  
  private void digest(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2) {
    Block block = this.memory[this.laneLength - 1];
    for (byte b = 1; b < this.parameters.getLanes(); b++) {
      int i = b * this.laneLength + this.laneLength - 1;
      block.xorWith(this.memory[i]);
    } 
    block.toBytes(paramArrayOfbyte1);
    hash(paramArrayOfbyte1, paramArrayOfbyte2, paramInt1, paramInt2);
  }
  
  private void hash(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = new byte[4];
    Pack.intToLittleEndian(paramInt2, arrayOfByte, 0);
    byte b = 64;
    if (paramInt2 <= b) {
      Blake2bDigest blake2bDigest = new Blake2bDigest(paramInt2 * 8);
      blake2bDigest.update(arrayOfByte, 0, arrayOfByte.length);
      blake2bDigest.update(paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
      blake2bDigest.doFinal(paramArrayOfbyte2, paramInt1);
    } else {
      Blake2bDigest blake2bDigest = new Blake2bDigest(b * 8);
      byte[] arrayOfByte1 = new byte[b];
      blake2bDigest.update(arrayOfByte, 0, arrayOfByte.length);
      blake2bDigest.update(paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
      blake2bDigest.doFinal(arrayOfByte1, 0);
      int i = b / 2;
      int j = paramInt1;
      System.arraycopy(arrayOfByte1, 0, paramArrayOfbyte2, j, i);
      j += i;
      int k = (paramInt2 + 31) / 32 - 2;
      int m = 2;
      while (m <= k) {
        blake2bDigest.update(arrayOfByte1, 0, arrayOfByte1.length);
        blake2bDigest.doFinal(arrayOfByte1, 0);
        System.arraycopy(arrayOfByte1, 0, paramArrayOfbyte2, j, i);
        m++;
        j += i;
      } 
      m = paramInt2 - 32 * k;
      blake2bDigest = new Blake2bDigest(m * 8);
      blake2bDigest.update(arrayOfByte1, 0, arrayOfByte1.length);
      blake2bDigest.doFinal(paramArrayOfbyte2, j);
    } 
  }
  
  private static void roundFunction(Block paramBlock, int paramInt1, int paramInt2, int paramInt3, int paramInt4, int paramInt5, int paramInt6, int paramInt7, int paramInt8, int paramInt9, int paramInt10, int paramInt11, int paramInt12, int paramInt13, int paramInt14, int paramInt15, int paramInt16) {
    long[] arrayOfLong = paramBlock.v;
    F(arrayOfLong, paramInt1, paramInt5, paramInt9, paramInt13);
    F(arrayOfLong, paramInt2, paramInt6, paramInt10, paramInt14);
    F(arrayOfLong, paramInt3, paramInt7, paramInt11, paramInt15);
    F(arrayOfLong, paramInt4, paramInt8, paramInt12, paramInt16);
    F(arrayOfLong, paramInt1, paramInt6, paramInt11, paramInt16);
    F(arrayOfLong, paramInt2, paramInt7, paramInt12, paramInt13);
    F(arrayOfLong, paramInt3, paramInt8, paramInt9, paramInt14);
    F(arrayOfLong, paramInt4, paramInt5, paramInt10, paramInt15);
  }
  
  private static void F(long[] paramArrayOflong, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    quarterRound(paramArrayOflong, paramInt1, paramInt2, paramInt4, 32);
    quarterRound(paramArrayOflong, paramInt3, paramInt4, paramInt2, 24);
    quarterRound(paramArrayOflong, paramInt1, paramInt2, paramInt4, 16);
    quarterRound(paramArrayOflong, paramInt3, paramInt4, paramInt2, 63);
  }
  
  private static void quarterRound(long[] paramArrayOflong, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    long l1 = paramArrayOflong[paramInt1];
    long l2 = paramArrayOflong[paramInt2];
    long l3 = paramArrayOflong[paramInt3];
    l1 += l2 + 2L * (l1 & 0xFFFFFFFFL) * (l2 & 0xFFFFFFFFL);
    l3 = Longs.rotateRight(l3 ^ l1, paramInt4);
    paramArrayOflong[paramInt1] = l1;
    paramArrayOflong[paramInt3] = l3;
  }
  
  private void initialize(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    Blake2bDigest blake2bDigest = new Blake2bDigest(512);
    int[] arrayOfInt = { this.parameters.getLanes(), paramInt, this.parameters.getMemory(), this.parameters.getIterations(), this.parameters.getVersion(), this.parameters.getType() };
    Pack.intToLittleEndian(arrayOfInt, paramArrayOfbyte1, 0);
    blake2bDigest.update(paramArrayOfbyte1, 0, arrayOfInt.length * 4);
    addByteString(paramArrayOfbyte1, blake2bDigest, paramArrayOfbyte2);
    addByteString(paramArrayOfbyte1, blake2bDigest, this.parameters.getSalt());
    addByteString(paramArrayOfbyte1, blake2bDigest, this.parameters.getSecret());
    addByteString(paramArrayOfbyte1, blake2bDigest, this.parameters.getAdditional());
    byte[] arrayOfByte = new byte[72];
    blake2bDigest.doFinal(arrayOfByte, 0);
    fillFirstBlocks(paramArrayOfbyte1, arrayOfByte);
  }
  
  private static void addByteString(byte[] paramArrayOfbyte1, Digest paramDigest, byte[] paramArrayOfbyte2) {
    if (null == paramArrayOfbyte2) {
      paramDigest.update(ZERO_BYTES, 0, 4);
      return;
    } 
    Pack.intToLittleEndian(paramArrayOfbyte2.length, paramArrayOfbyte1, 0);
    paramDigest.update(paramArrayOfbyte1, 0, 4);
    paramDigest.update(paramArrayOfbyte2, 0, paramArrayOfbyte2.length);
  }
  
  private void fillFirstBlocks(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = new byte[72];
    System.arraycopy(paramArrayOfbyte2, 0, arrayOfByte, 0, 64);
    arrayOfByte[64] = 1;
    for (byte b = 0; b < this.parameters.getLanes(); b++) {
      Pack.intToLittleEndian(b, paramArrayOfbyte2, 68);
      Pack.intToLittleEndian(b, arrayOfByte, 68);
      hash(paramArrayOfbyte2, paramArrayOfbyte1, 0, 1024);
      this.memory[b * this.laneLength + 0].fromBytes(paramArrayOfbyte1);
      hash(arrayOfByte, paramArrayOfbyte1, 0, 1024);
      this.memory[b * this.laneLength + 1].fromBytes(paramArrayOfbyte1);
    } 
  }
  
  private long intToLong(int paramInt) {
    return paramInt & 0xFFFFFFFFL;
  }
  
  private static class Block {
    private static final int SIZE = 128;
    
    private final long[] v = new long[128];
    
    private Block() {}
    
    void fromBytes(byte[] param1ArrayOfbyte) {
      if (param1ArrayOfbyte.length < 1024)
        throw new IllegalArgumentException("input shorter than blocksize"); 
      Pack.littleEndianToLong(param1ArrayOfbyte, 0, this.v);
    }
    
    void toBytes(byte[] param1ArrayOfbyte) {
      if (param1ArrayOfbyte.length < 1024)
        throw new IllegalArgumentException("output shorter than blocksize"); 
      Pack.longToLittleEndian(this.v, param1ArrayOfbyte, 0);
    }
    
    private void copyBlock(Block param1Block) {
      System.arraycopy(param1Block.v, 0, this.v, 0, 128);
    }
    
    private void xor(Block param1Block1, Block param1Block2) {
      long[] arrayOfLong1 = this.v;
      long[] arrayOfLong2 = param1Block1.v;
      long[] arrayOfLong3 = param1Block2.v;
      for (byte b = 0; b < ''; b++)
        arrayOfLong1[b] = arrayOfLong2[b] ^ arrayOfLong3[b]; 
    }
    
    private void xorWith(Block param1Block) {
      long[] arrayOfLong1 = this.v;
      long[] arrayOfLong2 = param1Block.v;
      for (byte b = 0; b < ''; b++)
        arrayOfLong1[b] = arrayOfLong1[b] ^ arrayOfLong2[b]; 
    }
    
    private void xorWith(Block param1Block1, Block param1Block2) {
      long[] arrayOfLong1 = this.v;
      long[] arrayOfLong2 = param1Block1.v;
      long[] arrayOfLong3 = param1Block2.v;
      for (byte b = 0; b < ''; b++)
        arrayOfLong1[b] = arrayOfLong1[b] ^ arrayOfLong2[b] ^ arrayOfLong3[b]; 
    }
    
    public Block clear() {
      Arrays.fill(this.v, 0L);
      return this;
    }
  }
  
  private static class FillBlock {
    Argon2BytesGenerator.Block R = new Argon2BytesGenerator.Block();
    
    Argon2BytesGenerator.Block Z = new Argon2BytesGenerator.Block();
    
    Argon2BytesGenerator.Block addressBlock = new Argon2BytesGenerator.Block();
    
    Argon2BytesGenerator.Block inputBlock = new Argon2BytesGenerator.Block();
    
    private FillBlock() {}
    
    private void applyBlake() {
      byte b;
      for (b = 0; b < 8; b++) {
        int i = 16 * b;
        Argon2BytesGenerator.roundFunction(this.Z, i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7, i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15);
      } 
      for (b = 0; b < 8; b++) {
        int i = 2 * b;
        Argon2BytesGenerator.roundFunction(this.Z, i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49, i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113);
      } 
    }
    
    private void fillBlock(Argon2BytesGenerator.Block param1Block1, Argon2BytesGenerator.Block param1Block2) {
      this.Z.copyBlock(param1Block1);
      applyBlake();
      param1Block2.xor(param1Block1, this.Z);
    }
    
    private void fillBlock(Argon2BytesGenerator.Block param1Block1, Argon2BytesGenerator.Block param1Block2, Argon2BytesGenerator.Block param1Block3) {
      this.R.xor(param1Block1, param1Block2);
      this.Z.copyBlock(this.R);
      applyBlake();
      param1Block3.xor(this.R, this.Z);
    }
    
    private void fillBlockWithXor(Argon2BytesGenerator.Block param1Block1, Argon2BytesGenerator.Block param1Block2, Argon2BytesGenerator.Block param1Block3) {
      this.R.xor(param1Block1, param1Block2);
      this.Z.copyBlock(this.R);
      applyBlake();
      param1Block3.xorWith(this.R, this.Z);
    }
  }
  
  private static class Position {
    int pass;
    
    int lane;
    
    int slice;
  }
}
