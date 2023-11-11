package META-INF.versions.9.org.bouncycastle.asn1.sec;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECParametersHolder;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class SECNamedCurves {
  private static X9ECPoint configureBasepoint(ECCurve paramECCurve, String paramString) {
    X9ECPoint x9ECPoint = new X9ECPoint(paramECCurve, Hex.decodeStrict(paramString));
    WNafUtil.configureBasepoint(x9ECPoint.getPoint());
    return x9ECPoint;
  }
  
  private static ECCurve configureCurve(ECCurve paramECCurve) {
    return paramECCurve;
  }
  
  private static ECCurve configureCurveGLV(ECCurve paramECCurve, GLVTypeBParameters paramGLVTypeBParameters) {
    return paramECCurve.configure().setEndomorphism(new GLVTypeBEndomorphism(paramECCurve, paramGLVTypeBParameters)).create();
  }
  
  private static BigInteger fromHex(String paramString) {
    return new BigInteger(1, Hex.decodeStrict(paramString));
  }
  
  static X9ECParametersHolder secp112r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp112r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp128r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp128r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp160k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp160r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp160r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp192k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp192r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp224k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp224r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp256k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp256r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp384r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp521r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect113r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect113r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect131r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect131r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect163k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect163r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect163r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect193r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect193r2 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect233k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect233r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect239k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect283k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect283r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect409k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect409r1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect571k1 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder sect571r1 = (X9ECParametersHolder)new Object();
  
  static final Hashtable objIds = new Hashtable<>();
  
  static final Hashtable curves = new Hashtable<>();
  
  static final Hashtable names = new Hashtable<>();
  
  static void defineCurve(String paramString, ASN1ObjectIdentifier paramASN1ObjectIdentifier, X9ECParametersHolder paramX9ECParametersHolder) {
    objIds.put(paramString, paramASN1ObjectIdentifier);
    names.put(paramASN1ObjectIdentifier, paramString);
    curves.put(paramASN1ObjectIdentifier, paramX9ECParametersHolder);
  }
  
  static {
    defineCurve("secp112r1", SECObjectIdentifiers.secp112r1, secp112r1);
    defineCurve("secp112r2", SECObjectIdentifiers.secp112r2, secp112r2);
    defineCurve("secp128r1", SECObjectIdentifiers.secp128r1, secp128r1);
    defineCurve("secp128r2", SECObjectIdentifiers.secp128r2, secp128r2);
    defineCurve("secp160k1", SECObjectIdentifiers.secp160k1, secp160k1);
    defineCurve("secp160r1", SECObjectIdentifiers.secp160r1, secp160r1);
    defineCurve("secp160r2", SECObjectIdentifiers.secp160r2, secp160r2);
    defineCurve("secp192k1", SECObjectIdentifiers.secp192k1, secp192k1);
    defineCurve("secp192r1", SECObjectIdentifiers.secp192r1, secp192r1);
    defineCurve("secp224k1", SECObjectIdentifiers.secp224k1, secp224k1);
    defineCurve("secp224r1", SECObjectIdentifiers.secp224r1, secp224r1);
    defineCurve("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1);
    defineCurve("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1);
    defineCurve("secp384r1", SECObjectIdentifiers.secp384r1, secp384r1);
    defineCurve("secp521r1", SECObjectIdentifiers.secp521r1, secp521r1);
    defineCurve("sect113r1", SECObjectIdentifiers.sect113r1, sect113r1);
    defineCurve("sect113r2", SECObjectIdentifiers.sect113r2, sect113r2);
    defineCurve("sect131r1", SECObjectIdentifiers.sect131r1, sect131r1);
    defineCurve("sect131r2", SECObjectIdentifiers.sect131r2, sect131r2);
    defineCurve("sect163k1", SECObjectIdentifiers.sect163k1, sect163k1);
    defineCurve("sect163r1", SECObjectIdentifiers.sect163r1, sect163r1);
    defineCurve("sect163r2", SECObjectIdentifiers.sect163r2, sect163r2);
    defineCurve("sect193r1", SECObjectIdentifiers.sect193r1, sect193r1);
    defineCurve("sect193r2", SECObjectIdentifiers.sect193r2, sect193r2);
    defineCurve("sect233k1", SECObjectIdentifiers.sect233k1, sect233k1);
    defineCurve("sect233r1", SECObjectIdentifiers.sect233r1, sect233r1);
    defineCurve("sect239k1", SECObjectIdentifiers.sect239k1, sect239k1);
    defineCurve("sect283k1", SECObjectIdentifiers.sect283k1, sect283k1);
    defineCurve("sect283r1", SECObjectIdentifiers.sect283r1, sect283r1);
    defineCurve("sect409k1", SECObjectIdentifiers.sect409k1, sect409k1);
    defineCurve("sect409r1", SECObjectIdentifiers.sect409r1, sect409r1);
    defineCurve("sect571k1", SECObjectIdentifiers.sect571k1, sect571k1);
    defineCurve("sect571r1", SECObjectIdentifiers.sect571r1, sect571r1);
  }
  
  public static X9ECParameters getByName(String paramString) {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = getOID(paramString);
    return (aSN1ObjectIdentifier == null) ? null : getByOID(aSN1ObjectIdentifier);
  }
  
  public static X9ECParameters getByOID(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    X9ECParametersHolder x9ECParametersHolder = (X9ECParametersHolder)curves.get(paramASN1ObjectIdentifier);
    return (x9ECParametersHolder == null) ? null : x9ECParametersHolder.getParameters();
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
}
