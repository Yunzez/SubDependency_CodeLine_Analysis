package org.bouncycastle.jcajce.util;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class PrivateKeyAnnotator {
  public static AnnotatedPrivateKey annotate(PrivateKey paramPrivateKey, String paramString) {
    return new AnnotatedPrivateKey(paramPrivateKey, paramString);
  }
  
  public static AnnotatedPrivateKey annotate(PrivateKey paramPrivateKey, Map<String, Object> paramMap) {
    HashMap<String, Object> hashMap = new HashMap<String, Object>(paramMap);
    return new AnnotatedPrivateKey(paramPrivateKey, Collections.unmodifiableMap(hashMap));
  }
}
