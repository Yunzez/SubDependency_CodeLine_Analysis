package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1Encodable;

public class ASN1EncodableVector {
  static final ASN1Encodable[] EMPTY_ELEMENTS = new ASN1Encodable[0];
  
  private static final int DEFAULT_CAPACITY = 10;
  
  private ASN1Encodable[] elements;
  
  private int elementCount;
  
  private boolean copyOnWrite;
  
  public ASN1EncodableVector() {
    this(10);
  }
  
  public ASN1EncodableVector(int paramInt) {
    if (paramInt < 0)
      throw new IllegalArgumentException("'initialCapacity' must not be negative"); 
    this.elements = (paramInt == 0) ? EMPTY_ELEMENTS : new ASN1Encodable[paramInt];
    this.elementCount = 0;
    this.copyOnWrite = false;
  }
  
  public void add(ASN1Encodable paramASN1Encodable) {
    if (null == paramASN1Encodable)
      throw new NullPointerException("'element' cannot be null"); 
    int i = this.elements.length;
    int j = this.elementCount + 1;
    if ((((j > i) ? 1 : 0) | this.copyOnWrite) != 0)
      reallocate(j); 
    this.elements[this.elementCount] = paramASN1Encodable;
    this.elementCount = j;
  }
  
  public void addAll(ASN1Encodable[] paramArrayOfASN1Encodable) {
    if (null == paramArrayOfASN1Encodable)
      throw new NullPointerException("'others' cannot be null"); 
    doAddAll(paramArrayOfASN1Encodable, "'others' elements cannot be null");
  }
  
  public void addAll(org.bouncycastle.asn1.ASN1EncodableVector paramASN1EncodableVector) {
    if (null == paramASN1EncodableVector)
      throw new NullPointerException("'other' cannot be null"); 
    doAddAll(paramASN1EncodableVector.elements, "'other' elements cannot be null");
  }
  
  private void doAddAll(ASN1Encodable[] paramArrayOfASN1Encodable, String paramString) {
    int i = paramArrayOfASN1Encodable.length;
    if (i < 1)
      return; 
    int j = this.elements.length;
    int k = this.elementCount + i;
    if ((((k > j) ? 1 : 0) | this.copyOnWrite) != 0)
      reallocate(k); 
    byte b = 0;
    do {
      ASN1Encodable aSN1Encodable = paramArrayOfASN1Encodable[b];
      if (null == aSN1Encodable)
        throw new NullPointerException(paramString); 
      this.elements[this.elementCount + b] = aSN1Encodable;
    } while (++b < i);
    this.elementCount = k;
  }
  
  public ASN1Encodable get(int paramInt) {
    if (paramInt >= this.elementCount)
      throw new ArrayIndexOutOfBoundsException("" + paramInt + " >= " + paramInt); 
    return this.elements[paramInt];
  }
  
  public int size() {
    return this.elementCount;
  }
  
  ASN1Encodable[] copyElements() {
    if (0 == this.elementCount)
      return EMPTY_ELEMENTS; 
    ASN1Encodable[] arrayOfASN1Encodable = new ASN1Encodable[this.elementCount];
    System.arraycopy(this.elements, 0, arrayOfASN1Encodable, 0, this.elementCount);
    return arrayOfASN1Encodable;
  }
  
  ASN1Encodable[] takeElements() {
    if (0 == this.elementCount)
      return EMPTY_ELEMENTS; 
    if (this.elements.length == this.elementCount) {
      this.copyOnWrite = true;
      return this.elements;
    } 
    ASN1Encodable[] arrayOfASN1Encodable = new ASN1Encodable[this.elementCount];
    System.arraycopy(this.elements, 0, arrayOfASN1Encodable, 0, this.elementCount);
    return arrayOfASN1Encodable;
  }
  
  private void reallocate(int paramInt) {
    int i = this.elements.length;
    int j = Math.max(i, paramInt + (paramInt >> 1));
    ASN1Encodable[] arrayOfASN1Encodable = new ASN1Encodable[j];
    System.arraycopy(this.elements, 0, arrayOfASN1Encodable, 0, this.elementCount);
    this.elements = arrayOfASN1Encodable;
    this.copyOnWrite = false;
  }
  
  static ASN1Encodable[] cloneElements(ASN1Encodable[] paramArrayOfASN1Encodable) {
    return (paramArrayOfASN1Encodable.length < 1) ? EMPTY_ELEMENTS : (ASN1Encodable[])paramArrayOfASN1Encodable.clone();
  }
}
