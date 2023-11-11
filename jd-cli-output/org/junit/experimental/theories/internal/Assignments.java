package org.junit.experimental.theories.internal;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import org.junit.experimental.theories.ParameterSignature;
import org.junit.experimental.theories.ParameterSupplier;
import org.junit.experimental.theories.ParametersSuppliedBy;
import org.junit.experimental.theories.PotentialAssignment;
import org.junit.runners.model.TestClass;

public class Assignments {
  private List<PotentialAssignment> fAssigned;
  
  private final List<ParameterSignature> fUnassigned;
  
  private final TestClass fClass;
  
  private Assignments(List<PotentialAssignment> assigned, List<ParameterSignature> unassigned, TestClass testClass) {
    this.fUnassigned = unassigned;
    this.fAssigned = assigned;
    this.fClass = testClass;
  }
  
  public static Assignments allUnassigned(Method testMethod, TestClass testClass) throws Exception {
    List<ParameterSignature> signatures = ParameterSignature.signatures(testClass.getOnlyConstructor());
    signatures.addAll(ParameterSignature.signatures(testMethod));
    return new Assignments(new ArrayList<PotentialAssignment>(), signatures, testClass);
  }
  
  public boolean isComplete() {
    return (this.fUnassigned.size() == 0);
  }
  
  public ParameterSignature nextUnassigned() {
    return this.fUnassigned.get(0);
  }
  
  public Assignments assignNext(PotentialAssignment source) {
    List<PotentialAssignment> assigned = new ArrayList<PotentialAssignment>(this.fAssigned);
    assigned.add(source);
    return new Assignments(assigned, this.fUnassigned.subList(1, this.fUnassigned.size()), this.fClass);
  }
  
  public Object[] getActualValues(int start, int stop, boolean nullsOk) throws PotentialAssignment.CouldNotGenerateValueException {
    Object[] values = new Object[stop - start];
    for (int i = start; i < stop; i++) {
      Object value = ((PotentialAssignment)this.fAssigned.get(i)).getValue();
      if (value == null && !nullsOk)
        throw new PotentialAssignment.CouldNotGenerateValueException(); 
      values[i - start] = value;
    } 
    return values;
  }
  
  public List<PotentialAssignment> potentialsForNextUnassigned() throws InstantiationException, IllegalAccessException {
    ParameterSignature unassigned = nextUnassigned();
    return getSupplier(unassigned).getValueSources(unassigned);
  }
  
  public ParameterSupplier getSupplier(ParameterSignature unassigned) throws InstantiationException, IllegalAccessException {
    ParameterSupplier supplier = getAnnotatedSupplier(unassigned);
    if (supplier != null)
      return supplier; 
    return new AllMembersSupplier(this.fClass);
  }
  
  public ParameterSupplier getAnnotatedSupplier(ParameterSignature unassigned) throws InstantiationException, IllegalAccessException {
    ParametersSuppliedBy annotation = unassigned.<ParametersSuppliedBy>findDeepAnnotation(ParametersSuppliedBy.class);
    if (annotation == null)
      return null; 
    return annotation.value().newInstance();
  }
  
  public Object[] getConstructorArguments(boolean nullsOk) throws PotentialAssignment.CouldNotGenerateValueException {
    return getActualValues(0, getConstructorParameterCount(), nullsOk);
  }
  
  public Object[] getMethodArguments(boolean nullsOk) throws PotentialAssignment.CouldNotGenerateValueException {
    return getActualValues(getConstructorParameterCount(), this.fAssigned.size(), nullsOk);
  }
  
  public Object[] getAllArguments(boolean nullsOk) throws PotentialAssignment.CouldNotGenerateValueException {
    return getActualValues(0, this.fAssigned.size(), nullsOk);
  }
  
  private int getConstructorParameterCount() {
    List<ParameterSignature> signatures = ParameterSignature.signatures(this.fClass.getOnlyConstructor());
    int constructorParameterCount = signatures.size();
    return constructorParameterCount;
  }
  
  public Object[] getArgumentStrings(boolean nullsOk) throws PotentialAssignment.CouldNotGenerateValueException {
    Object[] values = new Object[this.fAssigned.size()];
    for (int i = 0; i < values.length; i++)
      values[i] = ((PotentialAssignment)this.fAssigned.get(i)).getDescription(); 
    return values;
  }
}
