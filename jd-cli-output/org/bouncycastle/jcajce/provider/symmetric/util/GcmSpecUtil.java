package org.bouncycastle.jcajce.provider.symmetric.util;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.internal.asn1.cms.GCMParameters;
import org.bouncycastle.util.Integers;

public class GcmSpecUtil {
  static final Class gcmSpecClass = ClassUtil.loadClass(GcmSpecUtil.class, "javax.crypto.spec.GCMParameterSpec");
  
  static final Method tLen;
  
  static final Method iv;
  
  private static Method extractMethod(final String name) {
    try {
      return AccessController.<Method>doPrivileged(new PrivilegedExceptionAction<Method>() {
            public Object run() throws Exception {
              return GcmSpecUtil.gcmSpecClass.getDeclaredMethod(name, new Class[0]);
            }
          });
    } catch (PrivilegedActionException privilegedActionException) {
      return null;
    } 
  }
  
  public static boolean gcmSpecExists() {
    return (gcmSpecClass != null);
  }
  
  public static boolean isGcmSpec(AlgorithmParameterSpec paramAlgorithmParameterSpec) {
    return (gcmSpecClass != null && gcmSpecClass.isInstance(paramAlgorithmParameterSpec));
  }
  
  public static boolean isGcmSpec(Class paramClass) {
    return (gcmSpecClass == paramClass);
  }
  
  public static AlgorithmParameterSpec extractGcmSpec(ASN1Primitive paramASN1Primitive) throws InvalidParameterSpecException {
    try {
      GCMParameters gCMParameters = GCMParameters.getInstance(paramASN1Primitive);
      Constructor<AlgorithmParameterSpec> constructor = gcmSpecClass.getConstructor(new Class[] { int.class, byte[].class });
      return constructor.newInstance(new Object[] { Integers.valueOf(gCMParameters.getIcvLen() * 8), gCMParameters.getNonce() });
    } catch (NoSuchMethodException noSuchMethodException) {
      throw new InvalidParameterSpecException("No constructor found!");
    } catch (Exception exception) {
      throw new InvalidParameterSpecException("Construction failed: " + exception.getMessage());
    } 
  }
  
  static AEADParameters extractAeadParameters(final KeyParameter keyParam, final AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    try {
      return AccessController.<AEADParameters>doPrivileged(new PrivilegedExceptionAction<AEADParameters>() {
            public Object run() throws Exception {
              return new AEADParameters(keyParam, ((Integer)GcmSpecUtil.tLen.invoke(params, new Object[0])).intValue(), (byte[])GcmSpecUtil.iv.invoke(params, new Object[0]));
            }
          });
    } catch (Exception exception) {
      throw new InvalidAlgorithmParameterException("Cannot process GCMParameterSpec.");
    } 
  }
  
  public static GCMParameters extractGcmParameters(final AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
    try {
      return AccessController.<GCMParameters>doPrivileged(new PrivilegedExceptionAction<GCMParameters>() {
            public Object run() throws Exception {
              return new GCMParameters((byte[])GcmSpecUtil.iv.invoke(paramSpec, new Object[0]), ((Integer)GcmSpecUtil.tLen.invoke(paramSpec, new Object[0])).intValue() / 8);
            }
          });
    } catch (Exception exception) {
      throw new InvalidParameterSpecException("Cannot process GCMParameterSpec");
    } 
  }
  
  static {
    if (gcmSpecClass != null) {
      tLen = extractMethod("getTLen");
      iv = extractMethod("getIV");
    } else {
      tLen = null;
      iv = null;
    } 
  }
}
