package META-INF.versions.9.org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

public class RandUtils {
  static int nextInt(SecureRandom paramSecureRandom, int paramInt) {
    int i;
    int j;
    if ((paramInt & -paramInt) == paramInt)
      return (int)(paramInt * (paramSecureRandom.nextInt() >>> 1) >> 31L); 
    do {
      i = paramSecureRandom.nextInt() >>> 1;
      j = i % paramInt;
    } while (i - j + paramInt - 1 < 0);
    return j;
  }
}
