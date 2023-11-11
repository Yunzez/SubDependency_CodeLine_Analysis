package org.bouncycastle.crypto.util;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class DEROtherInfo {
  private final DERSequence sequence;
  
  private DEROtherInfo(DERSequence paramDERSequence) {
    this.sequence = paramDERSequence;
  }
  
  public byte[] getEncoded() throws IOException {
    return this.sequence.getEncoded();
  }
  
  public static final class Builder {
    private final AlgorithmIdentifier algorithmID;
    
    private final ASN1OctetString partyUVInfo;
    
    private final ASN1OctetString partyVInfo;
    
    private ASN1TaggedObject suppPubInfo;
    
    private ASN1TaggedObject suppPrivInfo;
    
    public Builder(AlgorithmIdentifier param1AlgorithmIdentifier, byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2) {
      this.algorithmID = param1AlgorithmIdentifier;
      this.partyUVInfo = DerUtil.getOctetString(param1ArrayOfbyte1);
      this.partyVInfo = DerUtil.getOctetString(param1ArrayOfbyte2);
    }
    
    public Builder withSuppPubInfo(byte[] param1ArrayOfbyte) {
      this.suppPubInfo = new DERTaggedObject(false, 0, DerUtil.getOctetString(param1ArrayOfbyte));
      return this;
    }
    
    public Builder withSuppPrivInfo(byte[] param1ArrayOfbyte) {
      this.suppPrivInfo = new DERTaggedObject(false, 1, DerUtil.getOctetString(param1ArrayOfbyte));
      return this;
    }
    
    public DEROtherInfo build() {
      ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
      aSN1EncodableVector.add(this.algorithmID);
      aSN1EncodableVector.add(this.partyUVInfo);
      aSN1EncodableVector.add(this.partyVInfo);
      if (this.suppPubInfo != null)
        aSN1EncodableVector.add(this.suppPubInfo); 
      if (this.suppPrivInfo != null)
        aSN1EncodableVector.add(this.suppPrivInfo); 
      return new DEROtherInfo(new DERSequence(aSN1EncodableVector));
    }
  }
}
