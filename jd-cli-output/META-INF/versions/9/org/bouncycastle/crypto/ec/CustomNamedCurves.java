package META-INF.versions.9.org.bouncycastle.crypto.ec;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
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

public class CustomNamedCurves {
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
  
  static X9ECParametersHolder curve25519 = (X9ECParametersHolder)new Object();
  
  static X9ECParametersHolder secp128r1 = (X9ECParametersHolder)new Object();
  
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
  
  static X9ECParametersHolder sm2p256v1 = (X9ECParametersHolder)new Object();
  
  static final Hashtable nameToCurve = new Hashtable<>();
  
  static final Hashtable nameToOID = new Hashtable<>();
  
  static final Hashtable oidToCurve = new Hashtable<>();
  
  static final Hashtable oidToName = new Hashtable<>();
  
  static final Vector names = new Vector();
  
  static void defineCurve(String paramString, X9ECParametersHolder paramX9ECParametersHolder) {
    names.addElement(paramString);
    paramString = Strings.toLowerCase(paramString);
    nameToCurve.put(paramString, paramX9ECParametersHolder);
  }
  
  static void defineCurveWithOID(String paramString, ASN1ObjectIdentifier paramASN1ObjectIdentifier, X9ECParametersHolder paramX9ECParametersHolder) {
    names.addElement(paramString);
    oidToName.put(paramASN1ObjectIdentifier, paramString);
    oidToCurve.put(paramASN1ObjectIdentifier, paramX9ECParametersHolder);
    paramString = Strings.toLowerCase(paramString);
    nameToOID.put(paramString, paramASN1ObjectIdentifier);
    nameToCurve.put(paramString, paramX9ECParametersHolder);
  }
  
  static void defineCurveAlias(String paramString, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    Object object = oidToCurve.get(paramASN1ObjectIdentifier);
    if (object == null)
      throw new IllegalStateException(); 
    paramString = Strings.toLowerCase(paramString);
    nameToOID.put(paramString, paramASN1ObjectIdentifier);
    nameToCurve.put(paramString, object);
  }
  
  static {
    defineCurveWithOID("curve25519", CryptlibObjectIdentifiers.curvey25519, curve25519);
    defineCurveWithOID("secp128r1", SECObjectIdentifiers.secp128r1, secp128r1);
    defineCurveWithOID("secp160k1", SECObjectIdentifiers.secp160k1, secp160k1);
    defineCurveWithOID("secp160r1", SECObjectIdentifiers.secp160r1, secp160r1);
    defineCurveWithOID("secp160r2", SECObjectIdentifiers.secp160r2, secp160r2);
    defineCurveWithOID("secp192k1", SECObjectIdentifiers.secp192k1, secp192k1);
    defineCurveWithOID("secp192r1", SECObjectIdentifiers.secp192r1, secp192r1);
    defineCurveWithOID("secp224k1", SECObjectIdentifiers.secp224k1, secp224k1);
    defineCurveWithOID("secp224r1", SECObjectIdentifiers.secp224r1, secp224r1);
    defineCurveWithOID("secp256k1", SECObjectIdentifiers.secp256k1, secp256k1);
    defineCurveWithOID("secp256r1", SECObjectIdentifiers.secp256r1, secp256r1);
    defineCurveWithOID("secp384r1", SECObjectIdentifiers.secp384r1, secp384r1);
    defineCurveWithOID("secp521r1", SECObjectIdentifiers.secp521r1, secp521r1);
    defineCurveWithOID("sect113r1", SECObjectIdentifiers.sect113r1, sect113r1);
    defineCurveWithOID("sect113r2", SECObjectIdentifiers.sect113r2, sect113r2);
    defineCurveWithOID("sect131r1", SECObjectIdentifiers.sect131r1, sect131r1);
    defineCurveWithOID("sect131r2", SECObjectIdentifiers.sect131r2, sect131r2);
    defineCurveWithOID("sect163k1", SECObjectIdentifiers.sect163k1, sect163k1);
    defineCurveWithOID("sect163r1", SECObjectIdentifiers.sect163r1, sect163r1);
    defineCurveWithOID("sect163r2", SECObjectIdentifiers.sect163r2, sect163r2);
    defineCurveWithOID("sect193r1", SECObjectIdentifiers.sect193r1, sect193r1);
    defineCurveWithOID("sect193r2", SECObjectIdentifiers.sect193r2, sect193r2);
    defineCurveWithOID("sect233k1", SECObjectIdentifiers.sect233k1, sect233k1);
    defineCurveWithOID("sect233r1", SECObjectIdentifiers.sect233r1, sect233r1);
    defineCurveWithOID("sect239k1", SECObjectIdentifiers.sect239k1, sect239k1);
    defineCurveWithOID("sect283k1", SECObjectIdentifiers.sect283k1, sect283k1);
    defineCurveWithOID("sect283r1", SECObjectIdentifiers.sect283r1, sect283r1);
    defineCurveWithOID("sect409k1", SECObjectIdentifiers.sect409k1, sect409k1);
    defineCurveWithOID("sect409r1", SECObjectIdentifiers.sect409r1, sect409r1);
    defineCurveWithOID("sect571k1", SECObjectIdentifiers.sect571k1, sect571k1);
    defineCurveWithOID("sect571r1", SECObjectIdentifiers.sect571r1, sect571r1);
    defineCurveWithOID("sm2p256v1", GMObjectIdentifiers.sm2p256v1, sm2p256v1);
    defineCurveAlias("B-163", SECObjectIdentifiers.sect163r2);
    defineCurveAlias("B-233", SECObjectIdentifiers.sect233r1);
    defineCurveAlias("B-283", SECObjectIdentifiers.sect283r1);
    defineCurveAlias("B-409", SECObjectIdentifiers.sect409r1);
    defineCurveAlias("B-571", SECObjectIdentifiers.sect571r1);
    defineCurveAlias("K-163", SECObjectIdentifiers.sect163k1);
    defineCurveAlias("K-233", SECObjectIdentifiers.sect233k1);
    defineCurveAlias("K-283", SECObjectIdentifiers.sect283k1);
    defineCurveAlias("K-409", SECObjectIdentifiers.sect409k1);
    defineCurveAlias("K-571", SECObjectIdentifiers.sect571k1);
    defineCurveAlias("P-192", SECObjectIdentifiers.secp192r1);
    defineCurveAlias("P-224", SECObjectIdentifiers.secp224r1);
    defineCurveAlias("P-256", SECObjectIdentifiers.secp256r1);
    defineCurveAlias("P-384", SECObjectIdentifiers.secp384r1);
    defineCurveAlias("P-521", SECObjectIdentifiers.secp521r1);
  }
  
  public static X9ECParameters getByName(String paramString) {
    X9ECParametersHolder x9ECParametersHolder = (X9ECParametersHolder)nameToCurve.get(Strings.toLowerCase(paramString));
    return (x9ECParametersHolder == null) ? null : x9ECParametersHolder.getParameters();
  }
  
  public static X9ECParameters getByOID(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    X9ECParametersHolder x9ECParametersHolder = (X9ECParametersHolder)oidToCurve.get(paramASN1ObjectIdentifier);
    return (x9ECParametersHolder == null) ? null : x9ECParametersHolder.getParameters();
  }
  
  public static ASN1ObjectIdentifier getOID(String paramString) {
    return (ASN1ObjectIdentifier)nameToOID.get(Strings.toLowerCase(paramString));
  }
  
  public static String getName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return (String)oidToName.get(paramASN1ObjectIdentifier);
  }
  
  public static Enumeration getNames() {
    return names.elements();
  }
}
