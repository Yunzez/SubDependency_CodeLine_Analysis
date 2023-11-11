package org.bouncycastle.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class CompositePrivateKey implements PrivateKey {
  private final List<PrivateKey> keys;
  
  public CompositePrivateKey(PrivateKey... paramVarArgs) {
    if (paramVarArgs == null || paramVarArgs.length == 0)
      throw new IllegalArgumentException("at least one public key must be provided"); 
    ArrayList<PrivateKey> arrayList = new ArrayList(paramVarArgs.length);
    for (byte b = 0; b != paramVarArgs.length; b++)
      arrayList.add(paramVarArgs[b]); 
    this.keys = Collections.unmodifiableList(arrayList);
  }
  
  public List<PrivateKey> getPrivateKeys() {
    return this.keys;
  }
  
  public String getAlgorithm() {
    return "Composite";
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public byte[] getEncoded() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    for (byte b = 0; b != this.keys.size(); b++)
      aSN1EncodableVector.add(PrivateKeyInfo.getInstance(((PrivateKey)this.keys.get(b)).getEncoded())); 
    try {
      return (new PrivateKeyInfo(new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite), new DERSequence(aSN1EncodableVector))).getEncoded("DER");
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to encode composite key: " + iOException.getMessage());
    } 
  }
  
  public int hashCode() {
    return this.keys.hashCode();
  }
  
  public boolean equals(Object paramObject) {
    return (paramObject == this) ? true : ((paramObject instanceof CompositePrivateKey) ? this.keys.equals(((CompositePrivateKey)paramObject).keys) : false);
  }
}
