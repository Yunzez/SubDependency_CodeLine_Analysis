package org.bouncycastle.jcajce.util;

import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class AnnotatedPrivateKey implements PrivateKey {
  public static final String LABEL = "label";
  
  private final PrivateKey key;
  
  private final Map<String, Object> annotations;
  
  AnnotatedPrivateKey(PrivateKey paramPrivateKey, String paramString) {
    this.key = paramPrivateKey;
    this.annotations = Collections.singletonMap("label", paramString);
  }
  
  AnnotatedPrivateKey(PrivateKey paramPrivateKey, Map<String, Object> paramMap) {
    this.key = paramPrivateKey;
    this.annotations = paramMap;
  }
  
  public PrivateKey getKey() {
    return this.key;
  }
  
  public Map<String, Object> getAnnotations() {
    return this.annotations;
  }
  
  public String getAlgorithm() {
    return this.key.getAlgorithm();
  }
  
  public Object getAnnotation(String paramString) {
    return this.annotations.get(paramString);
  }
  
  public AnnotatedPrivateKey addAnnotation(String paramString, Object paramObject) {
    HashMap<String, Object> hashMap = new HashMap<String, Object>(this.annotations);
    hashMap.put(paramString, paramObject);
    return new AnnotatedPrivateKey(this.key, Collections.unmodifiableMap(hashMap));
  }
  
  public AnnotatedPrivateKey removeAnnotation(String paramString) {
    HashMap<String, Object> hashMap = new HashMap<String, Object>(this.annotations);
    hashMap.remove(paramString);
    return new AnnotatedPrivateKey(this.key, Collections.unmodifiableMap(hashMap));
  }
  
  public String getFormat() {
    return this.key.getFormat();
  }
  
  public byte[] getEncoded() {
    return this.key.getEncoded();
  }
  
  public int hashCode() {
    return this.key.hashCode();
  }
  
  public boolean equals(Object paramObject) {
    return (paramObject instanceof AnnotatedPrivateKey) ? this.key.equals(((AnnotatedPrivateKey)paramObject).key) : this.key.equals(paramObject);
  }
  
  public String toString() {
    return this.annotations.containsKey("label") ? this.annotations.get("label").toString() : this.key.toString();
  }
}
