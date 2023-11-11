package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraintValidatorException;

public class PKIXNameConstraintValidator {
  org.bouncycastle.asn1.x509.PKIXNameConstraintValidator validator = new org.bouncycastle.asn1.x509.PKIXNameConstraintValidator();
  
  public int hashCode() {
    return this.validator.hashCode();
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof PKIXNameConstraintValidator))
      return false; 
    PKIXNameConstraintValidator pKIXNameConstraintValidator = (PKIXNameConstraintValidator)paramObject;
    return this.validator.equals(pKIXNameConstraintValidator.validator);
  }
  
  public void checkPermittedDN(ASN1Sequence paramASN1Sequence) throws PKIXNameConstraintValidatorException {
    try {
      this.validator.checkPermittedDN(X500Name.getInstance(paramASN1Sequence));
    } catch (NameConstraintValidatorException nameConstraintValidatorException) {
      throw new PKIXNameConstraintValidatorException(nameConstraintValidatorException.getMessage(), nameConstraintValidatorException);
    } 
  }
  
  public void checkExcludedDN(ASN1Sequence paramASN1Sequence) throws PKIXNameConstraintValidatorException {
    try {
      this.validator.checkExcludedDN(X500Name.getInstance(paramASN1Sequence));
    } catch (NameConstraintValidatorException nameConstraintValidatorException) {
      throw new PKIXNameConstraintValidatorException(nameConstraintValidatorException.getMessage(), nameConstraintValidatorException);
    } 
  }
  
  public void checkPermitted(GeneralName paramGeneralName) throws PKIXNameConstraintValidatorException {
    try {
      this.validator.checkPermitted(paramGeneralName);
    } catch (NameConstraintValidatorException nameConstraintValidatorException) {
      throw new PKIXNameConstraintValidatorException(nameConstraintValidatorException.getMessage(), nameConstraintValidatorException);
    } 
  }
  
  public void checkExcluded(GeneralName paramGeneralName) throws PKIXNameConstraintValidatorException {
    try {
      this.validator.checkExcluded(paramGeneralName);
    } catch (NameConstraintValidatorException nameConstraintValidatorException) {
      throw new PKIXNameConstraintValidatorException(nameConstraintValidatorException.getMessage(), nameConstraintValidatorException);
    } 
  }
  
  public void intersectPermittedSubtree(GeneralSubtree paramGeneralSubtree) {
    this.validator.intersectPermittedSubtree(paramGeneralSubtree);
  }
  
  public void intersectPermittedSubtree(GeneralSubtree[] paramArrayOfGeneralSubtree) {
    this.validator.intersectPermittedSubtree(paramArrayOfGeneralSubtree);
  }
  
  public void intersectEmptyPermittedSubtree(int paramInt) {
    this.validator.intersectEmptyPermittedSubtree(paramInt);
  }
  
  public void addExcludedSubtree(GeneralSubtree paramGeneralSubtree) {
    this.validator.addExcludedSubtree(paramGeneralSubtree);
  }
  
  public String toString() {
    return this.validator.toString();
  }
}
