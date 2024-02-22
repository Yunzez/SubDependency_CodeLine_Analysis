/*
 * Copyright (C) 2015 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.market.curve;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import org.joda.beans.Bean;
import org.joda.beans.BeanBuilder;
import org.joda.beans.ImmutableBean;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaBean;
import org.joda.beans.MetaProperty;
import org.joda.beans.gen.BeanDefinition;
import org.joda.beans.gen.PropertyDefinition;
import org.joda.beans.impl.direct.DirectMetaBean;
import org.joda.beans.impl.direct.DirectMetaProperty;
import org.joda.beans.impl.direct.DirectMetaPropertyMap;
import org.joda.beans.impl.direct.DirectPrivateBeanBuilder;

import com.google.common.collect.ImmutableList;
import com.opengamma.strata.collect.array.DoubleArray;
import com.opengamma.strata.collect.array.DoubleMatrix;

/**
 * Jacobian matrix information produced during curve calibration.
 * <p>
 * The inverse Jacobian matrix produced using curve calibration is stored here.
 * The information is used to calculate market quote sensitivity.
 */
@BeanDefinition(builderScope = "private")
public final class JacobianCalibrationMatrix
    implements ImmutableBean, Serializable {

  /**
   * The curve order.
   * This defines the order of the curves during calibration, which can be used
   * as a key to interpret the Jacobian matrix.
   */
  @PropertyDefinition(validate = "notNull")
  private final ImmutableList<CurveParameterSize> order;
  /**
   * The inverse Jacobian matrix produced during curve calibration.
   * This is the derivative of the curve parameters with respect to the market quotes.
   */
  @PropertyDefinition(validate = "notNull")
  private final DoubleMatrix jacobianMatrix;

  //-------------------------------------------------------------------------
  /**
   * Obtains an instance from the curve order and Jacobian matrix.
   * <p>
   * This creates an instance from the inverse Jacobian matrix produced during curve calibration.
   * This is the derivative of the curve parameters with respect to the market quotes.
   * The curve order defines the order of the curves during calibration, which
   * can be used as a key to interpret the matrix.
   * 
   * @param order  the order of the curves during calibration
   * @param jacobianMatrix  the inverse Jacobian matrix produced during curve calibration
   * @return the info
   */
  public static JacobianCalibrationMatrix of(List<CurveParameterSize> order, DoubleMatrix jacobianMatrix) {
    return new JacobianCalibrationMatrix(order, jacobianMatrix);
  }

  //-------------------------------------------------------------------------
  /**
   * Gets the total number of curves.
   * 
   * @return the number of curves
   */
  public int getCurveCount() {
    return order.size();
  }

  /**
   * Gets the total number of parameters.
   * 
   * @return the number of curves
   */
  public int getTotalParameterCount() {
    return order.stream()
        .mapToInt(CurveParameterSize::getParameterCount)
        .sum();
  }

  /**
   * Checks if this info contains the specified curve.
   * 
   * @param name  the curve to find
   * @return true if the curve is matched
   */
  public boolean containsCurve(CurveName name) {
    return order.stream().anyMatch(o -> o.getName().equals(name));
  }

  /**
   * Splits the array according to the curve order.
   * <p>
   * The input array must be of the same size as the total number of parameters.
   * The result consists of a map of arrays, where each array is the appropriate
   * section of the input array as defined by the curve order.
   * 
   * @param array  the array to split
   * @return a map splitting the array by curve name
   */
  public Map<CurveName, DoubleArray> splitValues(DoubleArray array) {
    LinkedHashMap<CurveName, DoubleArray> result = new LinkedHashMap<>();
    int start = 0;
    for (CurveParameterSize paramSizes : order) {
      int size = paramSizes.getParameterCount();
      result.put(paramSizes.getName(), array.subArray(start, start + size));
      start += size;
    }
    return result;
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code JacobianCalibrationMatrix}.
   * @return the meta-bean, not null
   */
  public static JacobianCalibrationMatrix.Meta meta() {
    return JacobianCalibrationMatrix.Meta.INSTANCE;
  }

  static {
    MetaBean.register(JacobianCalibrationMatrix.Meta.INSTANCE);
  }

  /**
   * The serialization version id.
   */
  private static final long serialVersionUID = 1L;

  private JacobianCalibrationMatrix(
      List<CurveParameterSize> order,
      DoubleMatrix jacobianMatrix) {
    JodaBeanUtils.notNull(order, "order");
    JodaBeanUtils.notNull(jacobianMatrix, "jacobianMatrix");
    this.order = ImmutableList.copyOf(order);
    this.jacobianMatrix = jacobianMatrix;
  }

  @Override
  public JacobianCalibrationMatrix.Meta metaBean() {
    return JacobianCalibrationMatrix.Meta.INSTANCE;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the curve order.
   * This defines the order of the curves during calibration, which can be used
   * as a key to interpret the Jacobian matrix.
   * @return the value of the property, not null
   */
  public ImmutableList<CurveParameterSize> getOrder() {
    return order;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the inverse Jacobian matrix produced during curve calibration.
   * This is the derivative of the curve parameters with respect to the market quotes.
   * @return the value of the property, not null
   */
  public DoubleMatrix getJacobianMatrix() {
    return jacobianMatrix;
  }

  //-----------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      JacobianCalibrationMatrix other = (JacobianCalibrationMatrix) obj;
      return JodaBeanUtils.equal(order, other.order) &&
          JodaBeanUtils.equal(jacobianMatrix, other.jacobianMatrix);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = getClass().hashCode();
    hash = hash * 31 + JodaBeanUtils.hashCode(order);
    hash = hash * 31 + JodaBeanUtils.hashCode(jacobianMatrix);
    return hash;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder(96);
    buf.append("JacobianCalibrationMatrix{");
    buf.append("order").append('=').append(JodaBeanUtils.toString(order)).append(',').append(' ');
    buf.append("jacobianMatrix").append('=').append(JodaBeanUtils.toString(jacobianMatrix));
    buf.append('}');
    return buf.toString();
  }

  //-----------------------------------------------------------------------
  /**
   * The meta-bean for {@code JacobianCalibrationMatrix}.
   */
  public static final class Meta extends DirectMetaBean {
    /**
     * The singleton instance of the meta-bean.
     */
    static final Meta INSTANCE = new Meta();

    /**
     * The meta-property for the {@code order} property.
     */
    @SuppressWarnings({"unchecked", "rawtypes" })
    private final MetaProperty<ImmutableList<CurveParameterSize>> order = DirectMetaProperty.ofImmutable(
        this, "order", JacobianCalibrationMatrix.class, (Class) ImmutableList.class);
    /**
     * The meta-property for the {@code jacobianMatrix} property.
     */
    private final MetaProperty<DoubleMatrix> jacobianMatrix = DirectMetaProperty.ofImmutable(
        this, "jacobianMatrix", JacobianCalibrationMatrix.class, DoubleMatrix.class);
    /**
     * The meta-properties.
     */
    private final Map<String, MetaProperty<?>> metaPropertyMap$ = new DirectMetaPropertyMap(
        this, null,
        "order",
        "jacobianMatrix");

    /**
     * Restricted constructor.
     */
    private Meta() {
    }

    @Override
    protected MetaProperty<?> metaPropertyGet(String propertyName) {
      switch (propertyName.hashCode()) {
        case 106006350:  // order
          return order;
        case 1656240056:  // jacobianMatrix
          return jacobianMatrix;
      }
      return super.metaPropertyGet(propertyName);
    }

    @Override
    public BeanBuilder<? extends JacobianCalibrationMatrix> builder() {
      return new JacobianCalibrationMatrix.Builder();
    }

    @Override
    public Class<? extends JacobianCalibrationMatrix> beanType() {
      return JacobianCalibrationMatrix.class;
    }

    @Override
    public Map<String, MetaProperty<?>> metaPropertyMap() {
      return metaPropertyMap$;
    }

    //-----------------------------------------------------------------------
    /**
     * The meta-property for the {@code order} property.
     * @return the meta-property, not null
     */
    public MetaProperty<ImmutableList<CurveParameterSize>> order() {
      return order;
    }

    /**
     * The meta-property for the {@code jacobianMatrix} property.
     * @return the meta-property, not null
     */
    public MetaProperty<DoubleMatrix> jacobianMatrix() {
      return jacobianMatrix;
    }

    //-----------------------------------------------------------------------
    @Override
    protected Object propertyGet(Bean bean, String propertyName, boolean quiet) {
      switch (propertyName.hashCode()) {
        case 106006350:  // order
          return ((JacobianCalibrationMatrix) bean).getOrder();
        case 1656240056:  // jacobianMatrix
          return ((JacobianCalibrationMatrix) bean).getJacobianMatrix();
      }
      return super.propertyGet(bean, propertyName, quiet);
    }

    @Override
    protected void propertySet(Bean bean, String propertyName, Object newValue, boolean quiet) {
      metaProperty(propertyName);
      if (quiet) {
        return;
      }
      throw new UnsupportedOperationException("Property cannot be written: " + propertyName);
    }

  }

  //-----------------------------------------------------------------------
  /**
   * The bean-builder for {@code JacobianCalibrationMatrix}.
   */
  private static final class Builder extends DirectPrivateBeanBuilder<JacobianCalibrationMatrix> {

    private List<CurveParameterSize> order = ImmutableList.of();
    private DoubleMatrix jacobianMatrix;

    /**
     * Restricted constructor.
     */
    private Builder() {
    }

    //-----------------------------------------------------------------------
    @Override
    public Object get(String propertyName) {
      switch (propertyName.hashCode()) {
        case 106006350:  // order
          return order;
        case 1656240056:  // jacobianMatrix
          return jacobianMatrix;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
    }

    @SuppressWarnings("unchecked")
    @Override
    public Builder set(String propertyName, Object newValue) {
      switch (propertyName.hashCode()) {
        case 106006350:  // order
          this.order = (List<CurveParameterSize>) newValue;
          break;
        case 1656240056:  // jacobianMatrix
          this.jacobianMatrix = (DoubleMatrix) newValue;
          break;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
      return this;
    }

    @Override
    public JacobianCalibrationMatrix build() {
      return new JacobianCalibrationMatrix(
          order,
          jacobianMatrix);
    }

    //-----------------------------------------------------------------------
    @Override
    public String toString() {
      StringBuilder buf = new StringBuilder(96);
      buf.append("JacobianCalibrationMatrix.Builder{");
      buf.append("order").append('=').append(JodaBeanUtils.toString(order)).append(',').append(' ');
      buf.append("jacobianMatrix").append('=').append(JodaBeanUtils.toString(jacobianMatrix));
      buf.append('}');
      return buf.toString();
    }

  }

  //-------------------------- AUTOGENERATED END --------------------------
}