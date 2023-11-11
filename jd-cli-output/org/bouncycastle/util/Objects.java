package org.bouncycastle.util;

public class Objects {
  public static boolean areEqual(Object paramObject1, Object paramObject2) {
    return (paramObject1 == paramObject2 || (null != paramObject1 && null != paramObject2 && paramObject1.equals(paramObject2)));
  }
  
  public static int hashCode(Object paramObject) {
    return (null == paramObject) ? 0 : paramObject.hashCode();
  }
}
