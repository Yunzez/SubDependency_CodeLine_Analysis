package META-INF.versions.9.org.bouncycastle.util;

public interface Memoable {
  org.bouncycastle.util.Memoable copy();
  
  void reset(org.bouncycastle.util.Memoable paramMemoable);
}
