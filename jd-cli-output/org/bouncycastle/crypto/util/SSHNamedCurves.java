package org.bouncycastle.crypto.util;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;

public class SSHNamedCurves {
  private static final Map<ASN1ObjectIdentifier, String> oidToName;
  
  private static final Map<String, ASN1ObjectIdentifier> oidMap = Collections.unmodifiableMap(new HashMap<String, ASN1ObjectIdentifier>() {
      
      });
  
  private static final Map<String, String> curveNameToSSHName = Collections.unmodifiableMap(new HashMap<String, String>() {
      
      });
  
  private static HashMap<ECCurve, String> curveMap = new HashMap<ECCurve, String>() {
    
    };
  
  public static ASN1ObjectIdentifier getByName(String paramString) {
    return oidMap.get(paramString);
  }
  
  public static X9ECParameters getParameters(String paramString) {
    return NISTNamedCurves.getByOID(oidMap.get(Strings.toLowerCase(paramString)));
  }
  
  public static X9ECParameters getParameters(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return NISTNamedCurves.getByOID(paramASN1ObjectIdentifier);
  }
  
  public static String getName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return oidToName.get(paramASN1ObjectIdentifier);
  }
  
  public static String getNameForParameters(ECDomainParameters paramECDomainParameters) {
    return (paramECDomainParameters instanceof ECNamedDomainParameters) ? getName(((ECNamedDomainParameters)paramECDomainParameters).getName()) : getNameForParameters(paramECDomainParameters.getCurve());
  }
  
  public static String getNameForParameters(ECCurve paramECCurve) {
    return curveNameToSSHName.get(curveMap.get(paramECCurve));
  }
  
  static {
    oidToName = Collections.unmodifiableMap(new HashMap<ASN1ObjectIdentifier, String>() {
        
        });
  }
}
