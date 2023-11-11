package META-INF.versions.9.org.bouncycastle.util;

import org.bouncycastle.util.Iterable;

public interface StringList extends Iterable<String> {
  boolean add(String paramString);
  
  String get(int paramInt);
  
  int size();
  
  String[] toStringArray();
  
  String[] toStringArray(int paramInt1, int paramInt2);
}
