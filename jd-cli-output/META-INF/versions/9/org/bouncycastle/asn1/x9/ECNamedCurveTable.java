package META-INF.versions.9.org.bouncycastle.asn1.x9;

import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.anssi.ANSSINamedCurves;
import org.bouncycastle.asn1.cryptlib.CryptlibObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;

public class ECNamedCurveTable {
  public static X9ECParameters getByName(String paramString) {
    X9ECParameters x9ECParameters = X962NamedCurves.getByName(paramString);
    if (x9ECParameters == null)
      x9ECParameters = SECNamedCurves.getByName(paramString); 
    if (x9ECParameters == null)
      x9ECParameters = NISTNamedCurves.getByName(paramString); 
    if (x9ECParameters == null)
      x9ECParameters = TeleTrusTNamedCurves.getByName(paramString); 
    if (x9ECParameters == null)
      x9ECParameters = ANSSINamedCurves.getByName(paramString); 
    if (x9ECParameters == null)
      x9ECParameters = ECGOST3410NamedCurves.getByNameX9(paramString); 
    if (x9ECParameters == null)
      x9ECParameters = GMNamedCurves.getByName(paramString); 
    return x9ECParameters;
  }
  
  public static ASN1ObjectIdentifier getOID(String paramString) {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = X962NamedCurves.getOID(paramString);
    if (aSN1ObjectIdentifier == null)
      aSN1ObjectIdentifier = SECNamedCurves.getOID(paramString); 
    if (aSN1ObjectIdentifier == null)
      aSN1ObjectIdentifier = NISTNamedCurves.getOID(paramString); 
    if (aSN1ObjectIdentifier == null)
      aSN1ObjectIdentifier = TeleTrusTNamedCurves.getOID(paramString); 
    if (aSN1ObjectIdentifier == null)
      aSN1ObjectIdentifier = ANSSINamedCurves.getOID(paramString); 
    if (aSN1ObjectIdentifier == null)
      aSN1ObjectIdentifier = ECGOST3410NamedCurves.getOID(paramString); 
    if (aSN1ObjectIdentifier == null)
      aSN1ObjectIdentifier = GMNamedCurves.getOID(paramString); 
    if (aSN1ObjectIdentifier == null && paramString.equals("curve25519"))
      aSN1ObjectIdentifier = CryptlibObjectIdentifiers.curvey25519; 
    return aSN1ObjectIdentifier;
  }
  
  public static String getName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    String str = X962NamedCurves.getName(paramASN1ObjectIdentifier);
    if (str == null)
      str = SECNamedCurves.getName(paramASN1ObjectIdentifier); 
    if (str == null)
      str = NISTNamedCurves.getName(paramASN1ObjectIdentifier); 
    if (str == null)
      str = TeleTrusTNamedCurves.getName(paramASN1ObjectIdentifier); 
    if (str == null)
      str = ANSSINamedCurves.getName(paramASN1ObjectIdentifier); 
    if (str == null)
      str = ECGOST3410NamedCurves.getName(paramASN1ObjectIdentifier); 
    if (str == null)
      str = GMNamedCurves.getName(paramASN1ObjectIdentifier); 
    if (str == null)
      str = CustomNamedCurves.getName(paramASN1ObjectIdentifier); 
    return str;
  }
  
  public static X9ECParameters getByOID(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    X9ECParameters x9ECParameters = X962NamedCurves.getByOID(paramASN1ObjectIdentifier);
    if (x9ECParameters == null)
      x9ECParameters = SECNamedCurves.getByOID(paramASN1ObjectIdentifier); 
    if (x9ECParameters == null)
      x9ECParameters = TeleTrusTNamedCurves.getByOID(paramASN1ObjectIdentifier); 
    if (x9ECParameters == null)
      x9ECParameters = ANSSINamedCurves.getByOID(paramASN1ObjectIdentifier); 
    if (x9ECParameters == null)
      x9ECParameters = ECGOST3410NamedCurves.getByOIDX9(paramASN1ObjectIdentifier); 
    if (x9ECParameters == null)
      x9ECParameters = GMNamedCurves.getByOID(paramASN1ObjectIdentifier); 
    return x9ECParameters;
  }
  
  public static Enumeration getNames() {
    Vector vector = new Vector();
    addEnumeration(vector, X962NamedCurves.getNames());
    addEnumeration(vector, SECNamedCurves.getNames());
    addEnumeration(vector, NISTNamedCurves.getNames());
    addEnumeration(vector, TeleTrusTNamedCurves.getNames());
    addEnumeration(vector, ANSSINamedCurves.getNames());
    addEnumeration(vector, ECGOST3410NamedCurves.getNames());
    addEnumeration(vector, GMNamedCurves.getNames());
    return vector.elements();
  }
  
  private static void addEnumeration(Vector paramVector, Enumeration paramEnumeration) {
    while (paramEnumeration.hasMoreElements())
      paramVector.addElement(paramEnumeration.nextElement()); 
  }
}
