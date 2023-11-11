package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

public class LEAEngine implements BlockCipher {
  private static final int BASEROUNDS = 16;
  
  private static final int NUMWORDS = 4;
  
  private static final int NUMWORDS128 = 4;
  
  private static final int MASK128 = 3;
  
  private static final int NUMWORDS192 = 6;
  
  private static final int NUMWORDS256 = 8;
  
  private static final int MASK256 = 7;
  
  private static final int BLOCKSIZE = 16;
  
  private static final int KEY0 = 0;
  
  private static final int KEY1 = 1;
  
  private static final int KEY2 = 2;
  
  private static final int KEY3 = 3;
  
  private static final int KEY4 = 4;
  
  private static final int KEY5 = 5;
  
  private static final int ROT1 = 1;
  
  private static final int ROT3 = 3;
  
  private static final int ROT5 = 5;
  
  private static final int ROT6 = 6;
  
  private static final int ROT9 = 9;
  
  private static final int ROT11 = 11;
  
  private static final int ROT13 = 13;
  
  private static final int ROT17 = 17;
  
  private static final int[] DELTA = new int[] { -1007687205, 1147300610, 2044886154, 2027892972, 1902027934, -947529206, -531697110, -440137385 };
  
  private final int[] theBlock = new int[4];
  
  private int theRounds;
  
  private int[][] theRoundKeys;
  
  private boolean forEncryption;
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    if (!(paramCipherParameters instanceof KeyParameter))
      throw new IllegalArgumentException("Invalid parameter passed to LEA init - " + paramCipherParameters.getClass().getName()); 
    byte[] arrayOfByte = ((KeyParameter)paramCipherParameters).getKey();
    int i = arrayOfByte.length;
    if ((i << 1) % 16 != 0 || i < 16 || i > 32)
      throw new IllegalArgumentException("KeyBitSize must be 128, 192 or 256"); 
    this.forEncryption = paramBoolean;
    generateRoundKeys(arrayOfByte);
  }
  
  public void reset() {}
  
  public String getAlgorithmName() {
    return "LEA";
  }
  
  public int getBlockSize() {
    return 16;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    checkBuffer(paramArrayOfbyte1, paramInt1, false);
    checkBuffer(paramArrayOfbyte2, paramInt2, true);
    return this.forEncryption ? encryptBlock(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2) : decryptBlock(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2);
  }
  
  private static int bufLength(byte[] paramArrayOfbyte) {
    return (paramArrayOfbyte == null) ? 0 : paramArrayOfbyte.length;
  }
  
  private static void checkBuffer(byte[] paramArrayOfbyte, int paramInt, boolean paramBoolean) {
    int i = bufLength(paramArrayOfbyte);
    int j = paramInt + 16;
    boolean bool = (paramInt < 0 || j < 0) ? true : false;
    if (bool || j > i)
      throw paramBoolean ? new OutputLengthException("Output buffer too short.") : new DataLengthException("Input buffer too short."); 
  }
  
  private int encryptBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1, this.theBlock, 0, 4);
    for (byte b = 0; b < this.theRounds; b++)
      encryptRound(b); 
    Pack.intToLittleEndian(this.theBlock, paramArrayOfbyte2, paramInt2);
    return 16;
  }
  
  private void encryptRound(int paramInt) {
    int[] arrayOfInt = this.theRoundKeys[paramInt];
    int i = (3 + paramInt) % 4;
    int j = leftIndex(i);
    this.theBlock[i] = ror32((this.theBlock[j] ^ arrayOfInt[4]) + (this.theBlock[i] ^ arrayOfInt[5]), 3);
    i = j;
    j = leftIndex(i);
    this.theBlock[i] = ror32((this.theBlock[j] ^ arrayOfInt[2]) + (this.theBlock[i] ^ arrayOfInt[3]), 5);
    i = j;
    j = leftIndex(i);
    this.theBlock[i] = rol32((this.theBlock[j] ^ arrayOfInt[0]) + (this.theBlock[i] ^ arrayOfInt[1]), 9);
  }
  
  private static int leftIndex(int paramInt) {
    return (paramInt == 0) ? 3 : (paramInt - 1);
  }
  
  private int decryptBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1, this.theBlock, 0, 4);
    for (int i = this.theRounds - 1; i >= 0; i--)
      decryptRound(i); 
    Pack.intToLittleEndian(this.theBlock, paramArrayOfbyte2, paramInt2);
    return 16;
  }
  
  private void decryptRound(int paramInt) {
    int[] arrayOfInt = this.theRoundKeys[paramInt];
    int i = paramInt % 4;
    int j = rightIndex(i);
    this.theBlock[j] = ror32(this.theBlock[j], 9) - (this.theBlock[i] ^ arrayOfInt[0]) ^ arrayOfInt[1];
    i = j;
    j = rightIndex(j);
    this.theBlock[j] = rol32(this.theBlock[j], 5) - (this.theBlock[i] ^ arrayOfInt[2]) ^ arrayOfInt[3];
    i = j;
    j = rightIndex(j);
    this.theBlock[j] = rol32(this.theBlock[j], 3) - (this.theBlock[i] ^ arrayOfInt[4]) ^ arrayOfInt[5];
  }
  
  private static int rightIndex(int paramInt) {
    return (paramInt == 3) ? 0 : (paramInt + 1);
  }
  
  private void generateRoundKeys(byte[] paramArrayOfbyte) {
    this.theRounds = (paramArrayOfbyte.length >> 1) + 16;
    this.theRoundKeys = new int[this.theRounds][6];
    int i = paramArrayOfbyte.length / 4;
    int[] arrayOfInt = new int[i];
    Pack.littleEndianToInt(paramArrayOfbyte, 0, arrayOfInt, 0, i);
    switch (i) {
      case 4:
        generate128RoundKeys(arrayOfInt);
        return;
      case 6:
        generate192RoundKeys(arrayOfInt);
        return;
    } 
    generate256RoundKeys(arrayOfInt);
  }
  
  private void generate128RoundKeys(int[] paramArrayOfint) {
    for (byte b = 0; b < this.theRounds; b++) {
      int i = rol32(DELTA[b & 0x3], b);
      byte b1 = 0;
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1++] + i, 1);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 3);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 6);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1), 11);
      int[] arrayOfInt = this.theRoundKeys[b];
      arrayOfInt[0] = paramArrayOfint[0];
      arrayOfInt[1] = paramArrayOfint[1];
      arrayOfInt[2] = paramArrayOfint[2];
      arrayOfInt[3] = paramArrayOfint[1];
      arrayOfInt[4] = paramArrayOfint[3];
      arrayOfInt[5] = paramArrayOfint[1];
    } 
  }
  
  private void generate192RoundKeys(int[] paramArrayOfint) {
    for (byte b = 0; b < this.theRounds; b++) {
      int i = rol32(DELTA[b % 6], b);
      byte b1 = 0;
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 1);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 3);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 6);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 11);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 13);
      paramArrayOfint[b1] = rol32(paramArrayOfint[b1] + rol32(i, b1++), 17);
      System.arraycopy(paramArrayOfint, 0, this.theRoundKeys[b], 0, b1);
    } 
  }
  
  private void generate256RoundKeys(int[] paramArrayOfint) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < this.theRounds; b2++) {
      int i = rol32(DELTA[b2 & 0x7], b2);
      int[] arrayOfInt = this.theRoundKeys[b2];
      byte b = 0;
      arrayOfInt[b] = rol32(paramArrayOfint[b1 & 0x7] + i, 1);
      paramArrayOfint[b1++ & 0x7] = arrayOfInt[b++];
      arrayOfInt[b] = rol32(paramArrayOfint[b1 & 0x7] + rol32(i, b), 3);
      paramArrayOfint[b1++ & 0x7] = arrayOfInt[b++];
      arrayOfInt[b] = rol32(paramArrayOfint[b1 & 0x7] + rol32(i, b), 6);
      paramArrayOfint[b1++ & 0x7] = arrayOfInt[b++];
      arrayOfInt[b] = rol32(paramArrayOfint[b1 & 0x7] + rol32(i, b), 11);
      paramArrayOfint[b1++ & 0x7] = arrayOfInt[b++];
      arrayOfInt[b] = rol32(paramArrayOfint[b1 & 0x7] + rol32(i, b), 13);
      paramArrayOfint[b1++ & 0x7] = arrayOfInt[b++];
      arrayOfInt[b] = rol32(paramArrayOfint[b1 & 0x7] + rol32(i, b), 17);
      paramArrayOfint[b1++ & 0x7] = arrayOfInt[b];
    } 
  }
  
  private static int rol32(int paramInt1, int paramInt2) {
    return paramInt1 << paramInt2 | paramInt1 >>> 32 - paramInt2;
  }
  
  private static int ror32(int paramInt1, int paramInt2) {
    return paramInt1 >>> paramInt2 | paramInt1 << 32 - paramInt2;
  }
}
