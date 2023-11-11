package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Iterator;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.LazyConstructionEnumeration;

class LazyEncodedSequence extends ASN1Sequence {
  private byte[] encoded;
  
  LazyEncodedSequence(byte[] paramArrayOfbyte) throws IOException {
    if (null == paramArrayOfbyte)
      throw new NullPointerException("'encoded' cannot be null"); 
    this.encoded = paramArrayOfbyte;
  }
  
  public ASN1Encodable getObjectAt(int paramInt) {
    force();
    return super.getObjectAt(paramInt);
  }
  
  public Enumeration getObjects() {
    byte[] arrayOfByte = getContents();
    if (null != arrayOfByte)
      return new LazyConstructionEnumeration(arrayOfByte); 
    return super.getObjects();
  }
  
  public int hashCode() {
    force();
    return super.hashCode();
  }
  
  public Iterator<ASN1Encodable> iterator() {
    force();
    return super.iterator();
  }
  
  public int size() {
    force();
    return super.size();
  }
  
  public ASN1Encodable[] toArray() {
    force();
    return super.toArray();
  }
  
  ASN1Encodable[] toArrayInternal() {
    force();
    return super.toArrayInternal();
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    byte[] arrayOfByte = getContents();
    if (null != arrayOfByte)
      return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, arrayOfByte.length); 
    return super.toDLObject().encodedLength(paramBoolean);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    byte[] arrayOfByte = getContents();
    if (null != arrayOfByte) {
      paramASN1OutputStream.writeEncodingDL(paramBoolean, 48, arrayOfByte);
      return;
    } 
    super.toDLObject().encode(paramASN1OutputStream, paramBoolean);
  }
  
  ASN1BitString toASN1BitString() {
    return ((ASN1Sequence)toDLObject()).toASN1BitString();
  }
  
  ASN1External toASN1External() {
    return ((ASN1Sequence)toDLObject()).toASN1External();
  }
  
  ASN1OctetString toASN1OctetString() {
    return ((ASN1Sequence)toDLObject()).toASN1OctetString();
  }
  
  ASN1Set toASN1Set() {
    return ((ASN1Sequence)toDLObject()).toASN1Set();
  }
  
  ASN1Primitive toDERObject() {
    force();
    return super.toDERObject();
  }
  
  ASN1Primitive toDLObject() {
    force();
    return super.toDLObject();
  }
  
  private synchronized void force() {
    if (null != this.encoded) {
      ASN1InputStream aSN1InputStream = new ASN1InputStream(this.encoded, true);
      try {
        ASN1EncodableVector aSN1EncodableVector = aSN1InputStream.readVector();
        aSN1InputStream.close();
        this.elements = aSN1EncodableVector.takeElements();
        this.encoded = null;
      } catch (IOException iOException) {
        throw new ASN1ParsingException("malformed ASN.1: " + iOException, iOException);
      } 
    } 
  }
  
  private synchronized byte[] getContents() {
    return this.encoded;
  }
}