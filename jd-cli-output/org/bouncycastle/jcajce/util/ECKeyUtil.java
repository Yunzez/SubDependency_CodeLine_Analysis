package org.bouncycastle.jcajce.util;

import java.io.IOException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECKeyUtil {
  public static ECPublicKey createKeyWithCompression(ECPublicKey paramECPublicKey) {
    return new ECPublicKeyWithCompression(paramECPublicKey);
  }
  
  private static class ECPublicKeyWithCompression implements ECPublicKey {
    private final ECPublicKey ecPublicKey;
    
    public ECPublicKeyWithCompression(ECPublicKey param1ECPublicKey) {
      this.ecPublicKey = param1ECPublicKey;
    }
    
    public ECPoint getW() {
      return this.ecPublicKey.getW();
    }
    
    public String getAlgorithm() {
      return this.ecPublicKey.getAlgorithm();
    }
    
    public String getFormat() {
      return this.ecPublicKey.getFormat();
    }
    
    public byte[] getEncoded() {
      ECCurve eCCurve;
      SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(this.ecPublicKey.getEncoded());
      X962Parameters x962Parameters = X962Parameters.getInstance(subjectPublicKeyInfo.getAlgorithm().getParameters());
      if (x962Parameters.isNamedCurve()) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier)x962Parameters.getParameters();
        X9ECParameters x9ECParameters = CustomNamedCurves.getByOID(aSN1ObjectIdentifier);
        if (x9ECParameters == null)
          x9ECParameters = ECNamedCurveTable.getByOID(aSN1ObjectIdentifier); 
        eCCurve = x9ECParameters.getCurve();
      } else {
        if (x962Parameters.isImplicitlyCA())
          throw new IllegalStateException("unable to identify implictlyCA"); 
        X9ECParameters x9ECParameters = X9ECParameters.getInstance(x962Parameters.getParameters());
        eCCurve = x9ECParameters.getCurve();
      } 
      ECPoint eCPoint = eCCurve.decodePoint(subjectPublicKeyInfo.getPublicKeyData().getOctets());
      ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance((new X9ECPoint(eCPoint, true)).toASN1Primitive());
      try {
        return (new SubjectPublicKeyInfo(subjectPublicKeyInfo.getAlgorithm(), aSN1OctetString.getOctets())).getEncoded();
      } catch (IOException iOException) {
        throw new IllegalStateException("unable to encode EC public key: " + iOException.getMessage());
      } 
    }
    
    public ECParameterSpec getParams() {
      return this.ecPublicKey.getParams();
    }
  }
}
