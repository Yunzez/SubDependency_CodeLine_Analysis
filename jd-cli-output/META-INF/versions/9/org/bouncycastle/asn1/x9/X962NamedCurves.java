package META-INF.versions.9.org.bouncycastle.asn1.x9;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class X962NamedCurves {
  private static X9ECPoint configureBasepoint(ECCurve paramECCurve, String paramString) {
    X9ECPoint x9ECPoint = new X9ECPoint(paramECCurve, Hex.decodeStrict(paramString));
    WNafUtil.configureBasepoint(x9ECPoint.getPoint());
    return x9ECPoint;
  }
  
  private static ECCurve configureCurve(ECCurve paramECCurve) {
    return paramECCurve;
  }
  
  private static BigInteger fromHex(String paramString) {
    return new BigInteger(1, Hex.decodeStrict(paramString));
  }
  
  static X9ECParametersHolder prime192v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder prime192v2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder prime192v3 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder prime239v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder prime239v2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder prime239v3 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder prime256v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb163v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb163v2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb163v3 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb176w1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb191v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb191v2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb191v3 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb208w1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb239v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb239v2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb239v3 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb272w1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb304w1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb359v1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2pnb368w1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder c2tnb431r1 = (X9ECParametersHolder)new Object();
  
  static final Hashtable objIds = new Hashtable<>();
  
  static final Hashtable curves = new Hashtable<>();
  
  static final Hashtable names = new Hashtable<>();
  
  static void defineCurve(String paramString, ASN1ObjectIdentifier paramASN1ObjectIdentifier, X9ECParametersHolder paramX9ECParametersHolder) {
    objIds.put(paramString, paramASN1ObjectIdentifier);
    names.put(paramASN1ObjectIdentifier, paramString);
    curves.put(paramASN1ObjectIdentifier, paramX9ECParametersHolder);
  }
  
  static {
    defineCurve("prime192v1", X9ObjectIdentifiers.prime192v1, prime192v1);
    defineCurve("prime192v2", X9ObjectIdentifiers.prime192v2, prime192v2);
    defineCurve("prime192v3", X9ObjectIdentifiers.prime192v3, prime192v3);
    defineCurve("prime239v1", X9ObjectIdentifiers.prime239v1, prime239v1);
    defineCurve("prime239v2", X9ObjectIdentifiers.prime239v2, prime239v2);
    defineCurve("prime239v3", X9ObjectIdentifiers.prime239v3, prime239v3);
    defineCurve("prime256v1", X9ObjectIdentifiers.prime256v1, prime256v1);
    defineCurve("c2pnb163v1", X9ObjectIdentifiers.c2pnb163v1, c2pnb163v1);
    defineCurve("c2pnb163v2", X9ObjectIdentifiers.c2pnb163v2, c2pnb163v2);
    defineCurve("c2pnb163v3", X9ObjectIdentifiers.c2pnb163v3, c2pnb163v3);
    defineCurve("c2pnb176w1", X9ObjectIdentifiers.c2pnb176w1, c2pnb176w1);
    defineCurve("c2tnb191v1", X9ObjectIdentifiers.c2tnb191v1, c2tnb191v1);
    defineCurve("c2tnb191v2", X9ObjectIdentifiers.c2tnb191v2, c2tnb191v2);
    defineCurve("c2tnb191v3", X9ObjectIdentifiers.c2tnb191v3, c2tnb191v3);
    defineCurve("c2pnb208w1", X9ObjectIdentifiers.c2pnb208w1, c2pnb208w1);
    defineCurve("c2tnb239v1", X9ObjectIdentifiers.c2tnb239v1, c2tnb239v1);
    defineCurve("c2tnb239v2", X9ObjectIdentifiers.c2tnb239v2, c2tnb239v2);
    defineCurve("c2tnb239v3", X9ObjectIdentifiers.c2tnb239v3, c2tnb239v3);
    defineCurve("c2pnb272w1", X9ObjectIdentifiers.c2pnb272w1, c2pnb272w1);
    defineCurve("c2pnb304w1", X9ObjectIdentifiers.c2pnb304w1, c2pnb304w1);
    defineCurve("c2tnb359v1", X9ObjectIdentifiers.c2tnb359v1, c2tnb359v1);
    defineCurve("c2pnb368w1", X9ObjectIdentifiers.c2pnb368w1, c2pnb368w1);
    defineCurve("c2tnb431r1", X9ObjectIdentifiers.c2tnb431r1, c2tnb431r1);
  }
  
  public static X9ECParameters getByName(String paramString) {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(paramString));
    if (aSN1ObjectIdentifier != null)
      return getByOID(aSN1ObjectIdentifier); 
    return null;
  }
  
  public static X9ECParameters getByOID(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    X9ECParametersHolder x9ECParametersHolder = (X9ECParametersHolder)curves.get(paramASN1ObjectIdentifier);
    if (x9ECParametersHolder != null)
      return x9ECParametersHolder.getParameters(); 
    return null;
  }
  
  public static ASN1ObjectIdentifier getOID(String paramString) {
    return (ASN1ObjectIdentifier)objIds.get(Strings.toLowerCase(paramString));
  }
  
  public static String getName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return (String)names.get(paramASN1ObjectIdentifier);
  }
  
  public static Enumeration getNames() {
    return objIds.keys();
  }
}
