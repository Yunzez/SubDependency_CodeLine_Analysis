package META-INF.versions.9.org.bouncycastle.asn1.teletrust;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class TeleTrusTNamedCurves {
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
  
  static X9ECParametersHolder brainpoolP160r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP160t1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP192r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP192t1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP224r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP224t1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP256r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP256t1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP320r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP320t1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP384r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP384t1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP512r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder brainpoolP512t1 = (X9ECParametersHolder)new Object();
  
  static final Hashtable objIds = new Hashtable<>();
  
  static final Hashtable curves = new Hashtable<>();
  
  static final Hashtable names = new Hashtable<>();
  
  static void defineCurve(String paramString, ASN1ObjectIdentifier paramASN1ObjectIdentifier, X9ECParametersHolder paramX9ECParametersHolder) {
    objIds.put(Strings.toLowerCase(paramString), paramASN1ObjectIdentifier);
    names.put(paramASN1ObjectIdentifier, paramString);
    curves.put(paramASN1ObjectIdentifier, paramX9ECParametersHolder);
  }
  
  static {
    defineCurve("brainpoolP160r1", TeleTrusTObjectIdentifiers.brainpoolP160r1, brainpoolP160r1);
    defineCurve("brainpoolP160t1", TeleTrusTObjectIdentifiers.brainpoolP160t1, brainpoolP160t1);
    defineCurve("brainpoolP192r1", TeleTrusTObjectIdentifiers.brainpoolP192r1, brainpoolP192r1);
    defineCurve("brainpoolP192t1", TeleTrusTObjectIdentifiers.brainpoolP192t1, brainpoolP192t1);
    defineCurve("brainpoolP224r1", TeleTrusTObjectIdentifiers.brainpoolP224r1, brainpoolP224r1);
    defineCurve("brainpoolP224t1", TeleTrusTObjectIdentifiers.brainpoolP224t1, brainpoolP224t1);
    defineCurve("brainpoolP256r1", TeleTrusTObjectIdentifiers.brainpoolP256r1, brainpoolP256r1);
    defineCurve("brainpoolP256t1", TeleTrusTObjectIdentifiers.brainpoolP256t1, brainpoolP256t1);
    defineCurve("brainpoolP320r1", TeleTrusTObjectIdentifiers.brainpoolP320r1, brainpoolP320r1);
    defineCurve("brainpoolP320t1", TeleTrusTObjectIdentifiers.brainpoolP320t1, brainpoolP320t1);
    defineCurve("brainpoolP384r1", TeleTrusTObjectIdentifiers.brainpoolP384r1, brainpoolP384r1);
    defineCurve("brainpoolP384t1", TeleTrusTObjectIdentifiers.brainpoolP384t1, brainpoolP384t1);
    defineCurve("brainpoolP512r1", TeleTrusTObjectIdentifiers.brainpoolP512r1, brainpoolP512r1);
    defineCurve("brainpoolP512t1", TeleTrusTObjectIdentifiers.brainpoolP512t1, brainpoolP512t1);
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
    return names.elements();
  }
  
  public static ASN1ObjectIdentifier getOID(short paramShort, boolean paramBoolean) {
    return getOID("brainpoolP" + paramShort + (paramBoolean ? "t" : "r") + "1");
  }
}
