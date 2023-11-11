package org.bouncycastle.jcajce.provider.asymmetric.ies;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.jce.spec.IESParameterSpec;

public class AlgorithmParametersSpi extends AlgorithmParametersSpi {
  IESParameterSpec currentSpec;
  
  protected boolean isASN1FormatString(String paramString) {
    return (paramString == null || paramString.equals("ASN.1"));
  }
  
  protected AlgorithmParameterSpec engineGetParameterSpec(Class paramClass) throws InvalidParameterSpecException {
    if (paramClass == null)
      throw new NullPointerException("argument to getParameterSpec must not be null"); 
    return localEngineGetParameterSpec(paramClass);
  }
  
  protected byte[] engineGetEncoded() {
    try {
      ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
      if (this.currentSpec.getDerivationV() != null)
        aSN1EncodableVector.add(new DERTaggedObject(false, 0, new DEROctetString(this.currentSpec.getDerivationV()))); 
      if (this.currentSpec.getEncodingV() != null)
        aSN1EncodableVector.add(new DERTaggedObject(false, 1, new DEROctetString(this.currentSpec.getEncodingV()))); 
      aSN1EncodableVector.add(new ASN1Integer(this.currentSpec.getMacKeySize()));
      if (this.currentSpec.getNonce() != null) {
        ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
        aSN1EncodableVector1.add(new ASN1Integer(this.currentSpec.getCipherKeySize()));
        aSN1EncodableVector1.add(new DEROctetString(this.currentSpec.getNonce()));
        aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector1));
      } 
      aSN1EncodableVector.add(this.currentSpec.getPointCompression() ? ASN1Boolean.TRUE : ASN1Boolean.FALSE);
      return (new DERSequence(aSN1EncodableVector)).getEncoded("DER");
    } catch (IOException iOException) {
      throw new RuntimeException("Error encoding IESParameters");
    } 
  }
  
  protected byte[] engineGetEncoded(String paramString) {
    return (isASN1FormatString(paramString) || paramString.equalsIgnoreCase("X.509")) ? engineGetEncoded() : null;
  }
  
  protected AlgorithmParameterSpec localEngineGetParameterSpec(Class<IESParameterSpec> paramClass) throws InvalidParameterSpecException {
    if (paramClass == IESParameterSpec.class || paramClass == AlgorithmParameterSpec.class)
      return this.currentSpec; 
    throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
  }
  
  protected void engineInit(AlgorithmParameterSpec paramAlgorithmParameterSpec) throws InvalidParameterSpecException {
    if (!(paramAlgorithmParameterSpec instanceof IESParameterSpec))
      throw new InvalidParameterSpecException("IESParameterSpec required to initialise a IES algorithm parameters object"); 
    this.currentSpec = (IESParameterSpec)paramAlgorithmParameterSpec;
  }
  
  protected void engineInit(byte[] paramArrayOfbyte) throws IOException {
    try {
      ASN1Sequence aSN1Sequence = (ASN1Sequence)ASN1Primitive.fromByteArray(paramArrayOfbyte);
      if (aSN1Sequence.size() > 5)
        throw new IOException("sequence too big"); 
      byte[] arrayOfByte1 = null;
      byte[] arrayOfByte2 = null;
      BigInteger bigInteger1 = null;
      BigInteger bigInteger2 = null;
      byte[] arrayOfByte3 = null;
      boolean bool = false;
      Enumeration<Object> enumeration = aSN1Sequence.getObjects();
      while (enumeration.hasMoreElements()) {
        Object object = enumeration.nextElement();
        if (object instanceof ASN1TaggedObject) {
          ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(object);
          if (aSN1TaggedObject.getTagNo() == 0) {
            arrayOfByte1 = ASN1OctetString.getInstance(aSN1TaggedObject, false).getOctets();
            continue;
          } 
          if (aSN1TaggedObject.getTagNo() == 1)
            arrayOfByte2 = ASN1OctetString.getInstance(aSN1TaggedObject, false).getOctets(); 
          continue;
        } 
        if (object instanceof ASN1Integer) {
          bigInteger1 = ASN1Integer.getInstance(object).getValue();
          continue;
        } 
        if (object instanceof ASN1Sequence) {
          ASN1Sequence aSN1Sequence1 = ASN1Sequence.getInstance(object);
          bigInteger2 = ASN1Integer.getInstance(aSN1Sequence1.getObjectAt(0)).getValue();
          arrayOfByte3 = ASN1OctetString.getInstance(aSN1Sequence1.getObjectAt(1)).getOctets();
          continue;
        } 
        if (object instanceof ASN1Boolean)
          bool = ASN1Boolean.getInstance(object).isTrue(); 
      } 
      if (bigInteger2 != null) {
        this.currentSpec = new IESParameterSpec(arrayOfByte1, arrayOfByte2, bigInteger1.intValue(), bigInteger2.intValue(), arrayOfByte3, bool);
      } else {
        this.currentSpec = new IESParameterSpec(arrayOfByte1, arrayOfByte2, bigInteger1.intValue(), -1, null, bool);
      } 
    } catch (ClassCastException classCastException) {
      throw new IOException("Not a valid IES Parameter encoding.");
    } catch (ArrayIndexOutOfBoundsException arrayIndexOutOfBoundsException) {
      throw new IOException("Not a valid IES Parameter encoding.");
    } 
  }
  
  protected void engineInit(byte[] paramArrayOfbyte, String paramString) throws IOException {
    if (isASN1FormatString(paramString) || paramString.equalsIgnoreCase("X.509")) {
      engineInit(paramArrayOfbyte);
    } else {
      throw new IOException("Unknown parameter format " + paramString);
    } 
  }
  
  protected String engineToString() {
    return "IES Parameters";
  }
}
