package org.bouncycastle.asn1;

abstract class ASN1Type {
  final Class javaClass;
  
  ASN1Type(Class paramClass) {
    this.javaClass = paramClass;
  }
  
  final Class getJavaClass() {
    return this.javaClass;
  }
  
  public final boolean equals(Object paramObject) {
    return (this == paramObject);
  }
  
  public final int hashCode() {
    return super.hashCode();
  }
}
