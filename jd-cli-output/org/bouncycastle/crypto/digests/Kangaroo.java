package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public final class Kangaroo {
  private static final int DIGESTLEN = 32;
  
  static abstract class KangarooBase implements ExtendedDigest, Xof {
    private static final int BLKSIZE = 8192;
    
    private static final byte[] SINGLE = new byte[] { 7 };
    
    private static final byte[] INTERMEDIATE = new byte[] { 11 };
    
    private static final byte[] FINAL = new byte[] { -1, -1, 6 };
    
    private static final byte[] FIRST = new byte[] { 3, 0, 0, 0, 0, 0, 0, 0 };
    
    private final byte[] singleByte = new byte[1];
    
    private final Kangaroo.KangarooSponge theTree;
    
    private final Kangaroo.KangarooSponge theLeaf;
    
    private final int theChainLen;
    
    private byte[] thePersonal;
    
    private boolean squeezing;
    
    private int theCurrNode;
    
    private int theProcessed;
    
    KangarooBase(int param1Int1, int param1Int2, int param1Int3) {
      this.theTree = new Kangaroo.KangarooSponge(param1Int1, param1Int2);
      this.theLeaf = new Kangaroo.KangarooSponge(param1Int1, param1Int2);
      this.theChainLen = param1Int1 >> 2;
      buildPersonal(null);
    }
    
    private void buildPersonal(byte[] param1ArrayOfbyte) {
      byte b = (param1ArrayOfbyte == null) ? 0 : param1ArrayOfbyte.length;
      byte[] arrayOfByte = lengthEncode(b);
      this.thePersonal = (param1ArrayOfbyte == null) ? new byte[b + arrayOfByte.length] : Arrays.copyOf(param1ArrayOfbyte, b + arrayOfByte.length);
      System.arraycopy(arrayOfByte, 0, this.thePersonal, b, arrayOfByte.length);
    }
    
    public int getByteLength() {
      return this.theTree.theRateBytes;
    }
    
    public int getDigestSize() {
      return this.theChainLen >> 1;
    }
    
    public void init(Kangaroo.KangarooParameters param1KangarooParameters) {
      buildPersonal(param1KangarooParameters.getPersonalisation());
      reset();
    }
    
    public void update(byte param1Byte) {
      this.singleByte[0] = param1Byte;
      update(this.singleByte, 0, 1);
    }
    
    public void update(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      processData(param1ArrayOfbyte, param1Int1, param1Int2);
    }
    
    public int doFinal(byte[] param1ArrayOfbyte, int param1Int) {
      return doFinal(param1ArrayOfbyte, param1Int, getDigestSize());
    }
    
    public int doFinal(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      if (this.squeezing)
        throw new IllegalStateException("Already outputting"); 
      int i = doOutput(param1ArrayOfbyte, param1Int1, param1Int2);
      reset();
      return i;
    }
    
    public int doOutput(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      if (!this.squeezing)
        switchToSqueezing(); 
      if (param1Int2 < 0)
        throw new IllegalArgumentException("Invalid output length"); 
      this.theTree.squeeze(param1ArrayOfbyte, param1Int1, param1Int2);
      return param1Int2;
    }
    
    private void processData(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      if (this.squeezing)
        throw new IllegalStateException("attempt to absorb while squeezing"); 
      Kangaroo.KangarooSponge kangarooSponge = (this.theCurrNode == 0) ? this.theTree : this.theLeaf;
      int i = 8192 - this.theProcessed;
      if (i >= param1Int2) {
        kangarooSponge.absorb(param1ArrayOfbyte, param1Int1, param1Int2);
        this.theProcessed += param1Int2;
        return;
      } 
      if (i > 0) {
        kangarooSponge.absorb(param1ArrayOfbyte, param1Int1, i);
        this.theProcessed += i;
      } 
      int j;
      for (j = i; j < param1Int2; j += k) {
        if (this.theProcessed == 8192)
          switchLeaf(true); 
        int k = Math.min(param1Int2 - j, 8192);
        this.theLeaf.absorb(param1ArrayOfbyte, param1Int1 + j, k);
        this.theProcessed += k;
      } 
    }
    
    public void reset() {
      this.theTree.initSponge();
      this.theLeaf.initSponge();
      this.theCurrNode = 0;
      this.theProcessed = 0;
      this.squeezing = false;
    }
    
    private void switchLeaf(boolean param1Boolean) {
      if (this.theCurrNode == 0) {
        this.theTree.absorb(FIRST, 0, FIRST.length);
      } else {
        this.theLeaf.absorb(INTERMEDIATE, 0, INTERMEDIATE.length);
        byte[] arrayOfByte = new byte[this.theChainLen];
        this.theLeaf.squeeze(arrayOfByte, 0, this.theChainLen);
        this.theTree.absorb(arrayOfByte, 0, this.theChainLen);
        this.theLeaf.initSponge();
      } 
      if (param1Boolean)
        this.theCurrNode++; 
      this.theProcessed = 0;
    }
    
    private void switchToSqueezing() {
      processData(this.thePersonal, 0, this.thePersonal.length);
      if (this.theCurrNode == 0) {
        switchSingle();
      } else {
        switchFinal();
      } 
    }
    
    private void switchSingle() {
      this.theTree.absorb(SINGLE, 0, 1);
      this.theTree.padAndSwitchToSqueezingPhase();
    }
    
    private void switchFinal() {
      switchLeaf(false);
      byte[] arrayOfByte = lengthEncode(this.theCurrNode);
      this.theTree.absorb(arrayOfByte, 0, arrayOfByte.length);
      this.theTree.absorb(FINAL, 0, FINAL.length);
      this.theTree.padAndSwitchToSqueezingPhase();
    }
    
    private static byte[] lengthEncode(long param1Long) {
      byte b = 0;
      long l = param1Long;
      if (l != 0L)
        for (b = 1; (l >>= 8L) != 0L; b = (byte)(b + 1)); 
      byte[] arrayOfByte = new byte[b + 1];
      arrayOfByte[b] = b;
      for (byte b1 = 0; b1 < b; b1++)
        arrayOfByte[b1] = (byte)(int)(param1Long >> 8 * (b - b1 - 1)); 
      return arrayOfByte;
    }
  }
  
  public static class KangarooParameters implements CipherParameters {
    private byte[] thePersonal;
    
    public byte[] getPersonalisation() {
      return Arrays.clone(this.thePersonal);
    }
    
    public static class Builder {
      private byte[] thePersonal;
      
      public Builder setPersonalisation(byte[] param2ArrayOfbyte) {
        this.thePersonal = Arrays.clone(param2ArrayOfbyte);
        return this;
      }
      
      public Kangaroo.KangarooParameters build() {
        Kangaroo.KangarooParameters kangarooParameters = new Kangaroo.KangarooParameters();
        if (this.thePersonal != null)
          kangarooParameters.thePersonal = this.thePersonal; 
        return kangarooParameters;
      }
    }
  }
  
  private static class KangarooSponge {
    private static long[] KeccakRoundConstants = new long[] { 
        1L, 32898L, -9223372036854742902L, -9223372034707259392L, 32907L, 2147483649L, -9223372034707259263L, -9223372036854743031L, 138L, 136L, 
        2147516425L, 2147483658L, 2147516555L, -9223372036854775669L, -9223372036854742903L, -9223372036854743037L, -9223372036854743038L, -9223372036854775680L, 32778L, -9223372034707292150L, 
        -9223372034707259263L, -9223372036854742912L, 2147483649L, -9223372034707259384L };
    
    private final int theRounds;
    
    private final int theRateBytes;
    
    private final long[] theState = new long[25];
    
    private final byte[] theQueue;
    
    private int bytesInQueue;
    
    private boolean squeezing;
    
    KangarooSponge(int param1Int1, int param1Int2) {
      this.theRateBytes = 1600 - (param1Int1 << 1) >> 3;
      this.theRounds = param1Int2;
      this.theQueue = new byte[this.theRateBytes];
      initSponge();
    }
    
    private void initSponge() {
      Arrays.fill(this.theState, 0L);
      Arrays.fill(this.theQueue, (byte)0);
      this.bytesInQueue = 0;
      this.squeezing = false;
    }
    
    private void absorb(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      if (this.squeezing)
        throw new IllegalStateException("attempt to absorb while squeezing"); 
      int i = 0;
      label17: while (i < param1Int2) {
        if (this.bytesInQueue == 0 && i <= param1Int2 - this.theRateBytes)
          while (true) {
            KangarooAbsorb(param1ArrayOfbyte, param1Int1 + i);
            i += this.theRateBytes;
            if (i > param1Int2 - this.theRateBytes)
              continue label17; 
          }  
        int j = Math.min(this.theRateBytes - this.bytesInQueue, param1Int2 - i);
        System.arraycopy(param1ArrayOfbyte, param1Int1 + i, this.theQueue, this.bytesInQueue, j);
        this.bytesInQueue += j;
        i += j;
        if (this.bytesInQueue == this.theRateBytes) {
          KangarooAbsorb(this.theQueue, 0);
          this.bytesInQueue = 0;
        } 
      } 
    }
    
    private void padAndSwitchToSqueezingPhase() {
      for (int i = this.bytesInQueue; i < this.theRateBytes; i++)
        this.theQueue[i] = 0; 
      this.theQueue[this.theRateBytes - 1] = (byte)(this.theQueue[this.theRateBytes - 1] ^ 0x80);
      KangarooAbsorb(this.theQueue, 0);
      KangarooExtract();
      this.bytesInQueue = this.theRateBytes;
      this.squeezing = true;
    }
    
    private void squeeze(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      if (!this.squeezing)
        padAndSwitchToSqueezingPhase(); 
      int i;
      for (i = 0; i < param1Int2; i += j) {
        if (this.bytesInQueue == 0) {
          KangarooPermutation();
          KangarooExtract();
          this.bytesInQueue = this.theRateBytes;
        } 
        int j = Math.min(this.bytesInQueue, param1Int2 - i);
        System.arraycopy(this.theQueue, this.theRateBytes - this.bytesInQueue, param1ArrayOfbyte, param1Int1 + i, j);
        this.bytesInQueue -= j;
      } 
    }
    
    private void KangarooAbsorb(byte[] param1ArrayOfbyte, int param1Int) {
      int i = this.theRateBytes >> 3;
      int j = param1Int;
      for (byte b = 0; b < i; b++) {
        this.theState[b] = this.theState[b] ^ Pack.littleEndianToLong(param1ArrayOfbyte, j);
        j += 8;
      } 
      KangarooPermutation();
    }
    
    private void KangarooExtract() {
      Pack.longToLittleEndian(this.theState, 0, this.theRateBytes >> 3, this.theQueue, 0);
    }
    
    private void KangarooPermutation() {
      long[] arrayOfLong = this.theState;
      long l1 = arrayOfLong[0];
      long l2 = arrayOfLong[1];
      long l3 = arrayOfLong[2];
      long l4 = arrayOfLong[3];
      long l5 = arrayOfLong[4];
      long l6 = arrayOfLong[5];
      long l7 = arrayOfLong[6];
      long l8 = arrayOfLong[7];
      long l9 = arrayOfLong[8];
      long l10 = arrayOfLong[9];
      long l11 = arrayOfLong[10];
      long l12 = arrayOfLong[11];
      long l13 = arrayOfLong[12];
      long l14 = arrayOfLong[13];
      long l15 = arrayOfLong[14];
      long l16 = arrayOfLong[15];
      long l17 = arrayOfLong[16];
      long l18 = arrayOfLong[17];
      long l19 = arrayOfLong[18];
      long l20 = arrayOfLong[19];
      long l21 = arrayOfLong[20];
      long l22 = arrayOfLong[21];
      long l23 = arrayOfLong[22];
      long l24 = arrayOfLong[23];
      long l25 = arrayOfLong[24];
      int i = KeccakRoundConstants.length - this.theRounds;
      for (byte b = 0; b < this.theRounds; b++) {
        long l26 = l1 ^ l6 ^ l11 ^ l16 ^ l21;
        long l27 = l2 ^ l7 ^ l12 ^ l17 ^ l22;
        long l28 = l3 ^ l8 ^ l13 ^ l18 ^ l23;
        long l29 = l4 ^ l9 ^ l14 ^ l19 ^ l24;
        long l30 = l5 ^ l10 ^ l15 ^ l20 ^ l25;
        long l31 = (l27 << 1L | l27 >>> -1L) ^ l30;
        long l32 = (l28 << 1L | l28 >>> -1L) ^ l26;
        long l33 = (l29 << 1L | l29 >>> -1L) ^ l27;
        long l34 = (l30 << 1L | l30 >>> -1L) ^ l28;
        long l35 = (l26 << 1L | l26 >>> -1L) ^ l29;
        l1 ^= l31;
        l6 ^= l31;
        l11 ^= l31;
        l16 ^= l31;
        l21 ^= l31;
        l2 ^= l32;
        l7 ^= l32;
        l12 ^= l32;
        l17 ^= l32;
        l22 ^= l32;
        l3 ^= l33;
        l8 ^= l33;
        l13 ^= l33;
        l18 ^= l33;
        l23 ^= l33;
        l4 ^= l34;
        l9 ^= l34;
        l14 ^= l34;
        l19 ^= l34;
        l24 ^= l34;
        l5 ^= l35;
        l10 ^= l35;
        l15 ^= l35;
        l20 ^= l35;
        l25 ^= l35;
        l27 = l2 << 1L | l2 >>> 63L;
        l2 = l7 << 44L | l7 >>> 20L;
        l7 = l10 << 20L | l10 >>> 44L;
        l10 = l23 << 61L | l23 >>> 3L;
        l23 = l15 << 39L | l15 >>> 25L;
        l15 = l21 << 18L | l21 >>> 46L;
        l21 = l3 << 62L | l3 >>> 2L;
        l3 = l13 << 43L | l13 >>> 21L;
        l13 = l14 << 25L | l14 >>> 39L;
        l14 = l20 << 8L | l20 >>> 56L;
        l20 = l24 << 56L | l24 >>> 8L;
        l24 = l16 << 41L | l16 >>> 23L;
        l16 = l5 << 27L | l5 >>> 37L;
        l5 = l25 << 14L | l25 >>> 50L;
        l25 = l22 << 2L | l22 >>> 62L;
        l22 = l9 << 55L | l9 >>> 9L;
        l9 = l17 << 45L | l17 >>> 19L;
        l17 = l6 << 36L | l6 >>> 28L;
        l6 = l4 << 28L | l4 >>> 36L;
        l4 = l19 << 21L | l19 >>> 43L;
        l19 = l18 << 15L | l18 >>> 49L;
        l18 = l12 << 10L | l12 >>> 54L;
        l12 = l8 << 6L | l8 >>> 58L;
        l8 = l11 << 3L | l11 >>> 61L;
        l11 = l27;
        l26 = l1 ^ (l2 ^ 0xFFFFFFFFFFFFFFFFL) & l3;
        l27 = l2 ^ (l3 ^ 0xFFFFFFFFFFFFFFFFL) & l4;
        l3 ^= (l4 ^ 0xFFFFFFFFFFFFFFFFL) & l5;
        l4 ^= (l5 ^ 0xFFFFFFFFFFFFFFFFL) & l1;
        l5 ^= (l1 ^ 0xFFFFFFFFFFFFFFFFL) & l2;
        l1 = l26;
        l2 = l27;
        l26 = l6 ^ (l7 ^ 0xFFFFFFFFFFFFFFFFL) & l8;
        l27 = l7 ^ (l8 ^ 0xFFFFFFFFFFFFFFFFL) & l9;
        l8 ^= (l9 ^ 0xFFFFFFFFFFFFFFFFL) & l10;
        l9 ^= (l10 ^ 0xFFFFFFFFFFFFFFFFL) & l6;
        l10 ^= (l6 ^ 0xFFFFFFFFFFFFFFFFL) & l7;
        l6 = l26;
        l7 = l27;
        l26 = l11 ^ (l12 ^ 0xFFFFFFFFFFFFFFFFL) & l13;
        l27 = l12 ^ (l13 ^ 0xFFFFFFFFFFFFFFFFL) & l14;
        l13 ^= (l14 ^ 0xFFFFFFFFFFFFFFFFL) & l15;
        l14 ^= (l15 ^ 0xFFFFFFFFFFFFFFFFL) & l11;
        l15 ^= (l11 ^ 0xFFFFFFFFFFFFFFFFL) & l12;
        l11 = l26;
        l12 = l27;
        l26 = l16 ^ (l17 ^ 0xFFFFFFFFFFFFFFFFL) & l18;
        l27 = l17 ^ (l18 ^ 0xFFFFFFFFFFFFFFFFL) & l19;
        l18 ^= (l19 ^ 0xFFFFFFFFFFFFFFFFL) & l20;
        l19 ^= (l20 ^ 0xFFFFFFFFFFFFFFFFL) & l16;
        l20 ^= (l16 ^ 0xFFFFFFFFFFFFFFFFL) & l17;
        l16 = l26;
        l17 = l27;
        l26 = l21 ^ (l22 ^ 0xFFFFFFFFFFFFFFFFL) & l23;
        l27 = l22 ^ (l23 ^ 0xFFFFFFFFFFFFFFFFL) & l24;
        l23 ^= (l24 ^ 0xFFFFFFFFFFFFFFFFL) & l25;
        l24 ^= (l25 ^ 0xFFFFFFFFFFFFFFFFL) & l21;
        l25 ^= (l21 ^ 0xFFFFFFFFFFFFFFFFL) & l22;
        l21 = l26;
        l22 = l27;
        l1 ^= KeccakRoundConstants[i + b];
      } 
      arrayOfLong[0] = l1;
      arrayOfLong[1] = l2;
      arrayOfLong[2] = l3;
      arrayOfLong[3] = l4;
      arrayOfLong[4] = l5;
      arrayOfLong[5] = l6;
      arrayOfLong[6] = l7;
      arrayOfLong[7] = l8;
      arrayOfLong[8] = l9;
      arrayOfLong[9] = l10;
      arrayOfLong[10] = l11;
      arrayOfLong[11] = l12;
      arrayOfLong[12] = l13;
      arrayOfLong[13] = l14;
      arrayOfLong[14] = l15;
      arrayOfLong[15] = l16;
      arrayOfLong[16] = l17;
      arrayOfLong[17] = l18;
      arrayOfLong[18] = l19;
      arrayOfLong[19] = l20;
      arrayOfLong[20] = l21;
      arrayOfLong[21] = l22;
      arrayOfLong[22] = l23;
      arrayOfLong[23] = l24;
      arrayOfLong[24] = l25;
    }
  }
  
  public static class KangarooTwelve extends KangarooBase {
    public KangarooTwelve() {
      this(32);
    }
    
    public KangarooTwelve(int param1Int) {
      super(128, 12, param1Int);
    }
    
    public String getAlgorithmName() {
      return "KangarooTwelve";
    }
  }
  
  public static class MarsupilamiFourteen extends KangarooBase {
    public MarsupilamiFourteen() {
      this(32);
    }
    
    public MarsupilamiFourteen(int param1Int) {
      super(256, 14, param1Int);
    }
    
    public String getAlgorithmName() {
      return "MarsupilamiFourteen";
    }
  }
}
