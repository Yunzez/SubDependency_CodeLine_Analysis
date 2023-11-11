package org.bouncycastle.math.raw;

public class Interleave {
  private static final long M32 = 1431655765L;
  
  private static final long M64 = 6148914691236517205L;
  
  private static final long M64R = -6148914691236517206L;
  
  public static int expand8to16(int paramInt) {
    paramInt &= 0xFF;
    paramInt = (paramInt | paramInt << 4) & 0xF0F;
    paramInt = (paramInt | paramInt << 2) & 0x3333;
    return (paramInt | paramInt << 1) & 0x5555;
  }
  
  public static int expand16to32(int paramInt) {
    paramInt &= 0xFFFF;
    paramInt = (paramInt | paramInt << 8) & 0xFF00FF;
    paramInt = (paramInt | paramInt << 4) & 0xF0F0F0F;
    paramInt = (paramInt | paramInt << 2) & 0x33333333;
    return (paramInt | paramInt << 1) & 0x55555555;
  }
  
  public static long expand32to64(int paramInt) {
    paramInt = Bits.bitPermuteStep(paramInt, 65280, 8);
    paramInt = Bits.bitPermuteStep(paramInt, 15728880, 4);
    paramInt = Bits.bitPermuteStep(paramInt, 202116108, 2);
    paramInt = Bits.bitPermuteStep(paramInt, 572662306, 1);
    return ((paramInt >>> 1) & 0x55555555L) << 32L | paramInt & 0x55555555L;
  }
  
  public static void expand64To128(long paramLong, long[] paramArrayOflong, int paramInt) {
    paramLong = Bits.bitPermuteStep(paramLong, 4294901760L, 16);
    paramLong = Bits.bitPermuteStep(paramLong, 280375465148160L, 8);
    paramLong = Bits.bitPermuteStep(paramLong, 67555025218437360L, 4);
    paramLong = Bits.bitPermuteStep(paramLong, 868082074056920076L, 2);
    paramLong = Bits.bitPermuteStep(paramLong, 2459565876494606882L, 1);
    paramArrayOflong[paramInt] = paramLong & 0x5555555555555555L;
    paramArrayOflong[paramInt + 1] = paramLong >>> 1L & 0x5555555555555555L;
  }
  
  public static void expand64To128(long[] paramArrayOflong1, int paramInt1, int paramInt2, long[] paramArrayOflong2, int paramInt3) {
    for (byte b = 0; b < paramInt2; b++) {
      expand64To128(paramArrayOflong1[paramInt1 + b], paramArrayOflong2, paramInt3);
      paramInt3 += 2;
    } 
  }
  
  public static void expand64To128Rev(long paramLong, long[] paramArrayOflong, int paramInt) {
    paramLong = Bits.bitPermuteStep(paramLong, 4294901760L, 16);
    paramLong = Bits.bitPermuteStep(paramLong, 280375465148160L, 8);
    paramLong = Bits.bitPermuteStep(paramLong, 67555025218437360L, 4);
    paramLong = Bits.bitPermuteStep(paramLong, 868082074056920076L, 2);
    paramLong = Bits.bitPermuteStep(paramLong, 2459565876494606882L, 1);
    paramArrayOflong[paramInt] = paramLong & 0xAAAAAAAAAAAAAAAAL;
    paramArrayOflong[paramInt + 1] = paramLong << 1L & 0xAAAAAAAAAAAAAAAAL;
  }
  
  public static int shuffle(int paramInt) {
    paramInt = Bits.bitPermuteStep(paramInt, 65280, 8);
    paramInt = Bits.bitPermuteStep(paramInt, 15728880, 4);
    paramInt = Bits.bitPermuteStep(paramInt, 202116108, 2);
    return Bits.bitPermuteStep(paramInt, 572662306, 1);
  }
  
  public static long shuffle(long paramLong) {
    paramLong = Bits.bitPermuteStep(paramLong, 4294901760L, 16);
    paramLong = Bits.bitPermuteStep(paramLong, 280375465148160L, 8);
    paramLong = Bits.bitPermuteStep(paramLong, 67555025218437360L, 4);
    paramLong = Bits.bitPermuteStep(paramLong, 868082074056920076L, 2);
    return Bits.bitPermuteStep(paramLong, 2459565876494606882L, 1);
  }
  
  public static int shuffle2(int paramInt) {
    paramInt = Bits.bitPermuteStep(paramInt, 11141290, 7);
    paramInt = Bits.bitPermuteStep(paramInt, 52428, 14);
    paramInt = Bits.bitPermuteStep(paramInt, 15728880, 4);
    return Bits.bitPermuteStep(paramInt, 65280, 8);
  }
  
  public static long shuffle2(long paramLong) {
    paramLong = Bits.bitPermuteStep(paramLong, 4278255360L, 24);
    paramLong = Bits.bitPermuteStep(paramLong, 57421771435671756L, 6);
    paramLong = Bits.bitPermuteStep(paramLong, 264913582878960L, 12);
    return Bits.bitPermuteStep(paramLong, 723401728380766730L, 3);
  }
  
  public static long shuffle3(long paramLong) {
    paramLong = Bits.bitPermuteStep(paramLong, 47851476196393130L, 7);
    paramLong = Bits.bitPermuteStep(paramLong, 225176545447116L, 14);
    return Bits.bitPermuteStep(paramLong, 4042322160L, 28);
  }
  
  public static int unshuffle(int paramInt) {
    paramInt = Bits.bitPermuteStep(paramInt, 572662306, 1);
    paramInt = Bits.bitPermuteStep(paramInt, 202116108, 2);
    paramInt = Bits.bitPermuteStep(paramInt, 15728880, 4);
    return Bits.bitPermuteStep(paramInt, 65280, 8);
  }
  
  public static long unshuffle(long paramLong) {
    paramLong = Bits.bitPermuteStep(paramLong, 2459565876494606882L, 1);
    paramLong = Bits.bitPermuteStep(paramLong, 868082074056920076L, 2);
    paramLong = Bits.bitPermuteStep(paramLong, 67555025218437360L, 4);
    paramLong = Bits.bitPermuteStep(paramLong, 280375465148160L, 8);
    return Bits.bitPermuteStep(paramLong, 4294901760L, 16);
  }
  
  public static int unshuffle2(int paramInt) {
    paramInt = Bits.bitPermuteStep(paramInt, 65280, 8);
    paramInt = Bits.bitPermuteStep(paramInt, 15728880, 4);
    paramInt = Bits.bitPermuteStep(paramInt, 52428, 14);
    return Bits.bitPermuteStep(paramInt, 11141290, 7);
  }
  
  public static long unshuffle2(long paramLong) {
    paramLong = Bits.bitPermuteStep(paramLong, 723401728380766730L, 3);
    paramLong = Bits.bitPermuteStep(paramLong, 264913582878960L, 12);
    paramLong = Bits.bitPermuteStep(paramLong, 57421771435671756L, 6);
    return Bits.bitPermuteStep(paramLong, 4278255360L, 24);
  }
  
  public static long unshuffle3(long paramLong) {
    return shuffle3(paramLong);
  }
}
