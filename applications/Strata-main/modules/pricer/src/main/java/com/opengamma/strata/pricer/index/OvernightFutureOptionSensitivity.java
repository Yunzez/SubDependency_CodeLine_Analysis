/*
 * Copyright (C) 2022 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.pricer.index;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.DoubleUnaryOperator;

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

import com.google.common.collect.ComparisonChain;
import com.opengamma.strata.basics.currency.Currency;
import com.opengamma.strata.basics.currency.FxRateProvider;
import com.opengamma.strata.market.sensitivity.MutablePointSensitivities;
import com.opengamma.strata.market.sensitivity.PointSensitivity;
import com.opengamma.strata.market.sensitivity.PointSensitivityBuilder;

/**
 * Point sensitivity to an implied volatility for a overnight future option model.
 * <p>
 * Holds the sensitivity to a specific volatility point.
 */
@BeanDefinition(builderScope = "private")
public final class OvernightFutureOptionSensitivity
    implements PointSensitivity, PointSensitivityBuilder, ImmutableBean, Serializable {

  /**
   * The name of the volatilities.
   */
  @PropertyDefinition(validate = "notNull")
  private final OvernightFutureOptionVolatilitiesName volatilitiesName;
  /**
   * The time to expiry of the option as a year fraction.
   */
  @PropertyDefinition(validate = "notNull")
  private final double expiry;
  /**
   * The fixing date of the underlying future.
   */
  @PropertyDefinition(validate = "notNull")
  private final LocalDate fixingDate;
  /**
   * The option strike price.
   */
  @PropertyDefinition
  private final double strikePrice;
  /**
   * The underlying future price.
   */
  @PropertyDefinition
  private final double futurePrice;
  /**
   * The currency of the sensitivity.
   */
  @PropertyDefinition(validate = "notNull", overrideGet = true)
  private final Currency currency;
  /**
   * The value of the sensitivity.
   */
  @PropertyDefinition(overrideGet = true)
  private final double sensitivity;

  //-------------------------------------------------------------------------
  /**
   * Obtains an instance.
   * 
   * @param volatilitiesName  the name of the volatilities
   * @param expiry  the expiry date-time of the option as a year fraction
   * @param fixingDate  the fixing date of the underlying future
   * @param strikePrice  the strike price of the option
   * @param futurePrice  the price of the underlying future
   * @param sensitivityCurrency  the currency of the sensitivity
   * @param sensitivity  the value of the sensitivity
   * @return the point sensitivity object
   */
  public static OvernightFutureOptionSensitivity of(
      OvernightFutureOptionVolatilitiesName volatilitiesName,
      double expiry,
      LocalDate fixingDate,
      double strikePrice,
      double futurePrice,
      Currency sensitivityCurrency,
      double sensitivity) {

    return new OvernightFutureOptionSensitivity(
        volatilitiesName, expiry, fixingDate, strikePrice, futurePrice, sensitivityCurrency, sensitivity);
  }

  //-------------------------------------------------------------------------
  @Override
  public OvernightFutureOptionSensitivity withCurrency(Currency currency) {
    if (this.currency.equals(currency)) {
      return this;
    }
    return new OvernightFutureOptionSensitivity(
        volatilitiesName, expiry, fixingDate, strikePrice, futurePrice, currency, sensitivity);
  }

  @Override
  public OvernightFutureOptionSensitivity withSensitivity(double sensitivity) {
    return new OvernightFutureOptionSensitivity(
        volatilitiesName, expiry, fixingDate, strikePrice, futurePrice, currency, sensitivity);
  }

  @Override
  public int compareKey(PointSensitivity other) {
    if (other instanceof OvernightFutureOptionSensitivity) {
      OvernightFutureOptionSensitivity otherOption = (OvernightFutureOptionSensitivity) other;
      return ComparisonChain.start()
          .compare(volatilitiesName, otherOption.volatilitiesName)
          .compare(currency, otherOption.currency)
          .compare(expiry, otherOption.expiry)
          .compare(fixingDate, otherOption.fixingDate)
          .compare(strikePrice, otherOption.strikePrice)
          .compare(futurePrice, otherOption.futurePrice)
          .result();
    }
    return getClass().getSimpleName().compareTo(other.getClass().getSimpleName());
  }

  @Override
  public OvernightFutureOptionSensitivity convertedTo(Currency resultCurrency, FxRateProvider rateProvider) {
    return (OvernightFutureOptionSensitivity) PointSensitivity.super.convertedTo(resultCurrency, rateProvider);
  }

  //-------------------------------------------------------------------------
  @Override
  public OvernightFutureOptionSensitivity multipliedBy(double factor) {
    return new OvernightFutureOptionSensitivity(
        volatilitiesName, expiry, fixingDate, strikePrice, futurePrice, currency, sensitivity * factor);
  }

  @Override
  public OvernightFutureOptionSensitivity mapSensitivity(DoubleUnaryOperator operator) {
    return new OvernightFutureOptionSensitivity(
        volatilitiesName, expiry, fixingDate, strikePrice, futurePrice, currency, operator.applyAsDouble(sensitivity));
  }

  @Override
  public OvernightFutureOptionSensitivity normalize() {
    return this;
  }

  @Override
  public MutablePointSensitivities buildInto(MutablePointSensitivities combination) {
    return combination.add(this);
  }

  @Override
  public OvernightFutureOptionSensitivity cloned() {
    return this;
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code OvernightFutureOptionSensitivity}.
   * @return the meta-bean, not null
   */
  public static OvernightFutureOptionSensitivity.Meta meta() {
    return OvernightFutureOptionSensitivity.Meta.INSTANCE;
  }

  static {
    MetaBean.register(OvernightFutureOptionSensitivity.Meta.INSTANCE);
  }

  /**
   * The serialization version id.
   */
  private static final long serialVersionUID = 1L;

  private OvernightFutureOptionSensitivity(
      OvernightFutureOptionVolatilitiesName volatilitiesName,
      double expiry,
      LocalDate fixingDate,
      double strikePrice,
      double futurePrice,
      Currency currency,
      double sensitivity) {
    JodaBeanUtils.notNull(volatilitiesName, "volatilitiesName");
    JodaBeanUtils.notNull(expiry, "expiry");
    JodaBeanUtils.notNull(fixingDate, "fixingDate");
    JodaBeanUtils.notNull(currency, "currency");
    this.volatilitiesName = volatilitiesName;
    this.expiry = expiry;
    this.fixingDate = fixingDate;
    this.strikePrice = strikePrice;
    this.futurePrice = futurePrice;
    this.currency = currency;
    this.sensitivity = sensitivity;
  }

  @Override
  public OvernightFutureOptionSensitivity.Meta metaBean() {
    return OvernightFutureOptionSensitivity.Meta.INSTANCE;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the name of the volatilities.
   * @return the value of the property, not null
   */
  public OvernightFutureOptionVolatilitiesName getVolatilitiesName() {
    return volatilitiesName;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the time to expiry of the option as a year fraction.
   * @return the value of the property, not null
   */
  public double getExpiry() {
    return expiry;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the fixing date of the underlying future.
   * @return the value of the property, not null
   */
  public LocalDate getFixingDate() {
    return fixingDate;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the option strike price.
   * @return the value of the property
   */
  public double getStrikePrice() {
    return strikePrice;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the underlying future price.
   * @return the value of the property
   */
  public double getFuturePrice() {
    return futurePrice;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the currency of the sensitivity.
   * @return the value of the property, not null
   */
  @Override
  public Currency getCurrency() {
    return currency;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the value of the sensitivity.
   * @return the value of the property
   */
  @Override
  public double getSensitivity() {
    return sensitivity;
  }

  //-----------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      OvernightFutureOptionSensitivity other = (OvernightFutureOptionSensitivity) obj;
      return JodaBeanUtils.equal(volatilitiesName, other.volatilitiesName) &&
          JodaBeanUtils.equal(expiry, other.expiry) &&
          JodaBeanUtils.equal(fixingDate, other.fixingDate) &&
          JodaBeanUtils.equal(strikePrice, other.strikePrice) &&
          JodaBeanUtils.equal(futurePrice, other.futurePrice) &&
          JodaBeanUtils.equal(currency, other.currency) &&
          JodaBeanUtils.equal(sensitivity, other.sensitivity);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = getClass().hashCode();
    hash = hash * 31 + JodaBeanUtils.hashCode(volatilitiesName);
    hash = hash * 31 + JodaBeanUtils.hashCode(expiry);
    hash = hash * 31 + JodaBeanUtils.hashCode(fixingDate);
    hash = hash * 31 + JodaBeanUtils.hashCode(strikePrice);
    hash = hash * 31 + JodaBeanUtils.hashCode(futurePrice);
    hash = hash * 31 + JodaBeanUtils.hashCode(currency);
    hash = hash * 31 + JodaBeanUtils.hashCode(sensitivity);
    return hash;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder(256);
    buf.append("OvernightFutureOptionSensitivity{");
    buf.append("volatilitiesName").append('=').append(JodaBeanUtils.toString(volatilitiesName)).append(',').append(' ');
    buf.append("expiry").append('=').append(JodaBeanUtils.toString(expiry)).append(',').append(' ');
    buf.append("fixingDate").append('=').append(JodaBeanUtils.toString(fixingDate)).append(',').append(' ');
    buf.append("strikePrice").append('=').append(JodaBeanUtils.toString(strikePrice)).append(',').append(' ');
    buf.append("futurePrice").append('=').append(JodaBeanUtils.toString(futurePrice)).append(',').append(' ');
    buf.append("currency").append('=').append(JodaBeanUtils.toString(currency)).append(',').append(' ');
    buf.append("sensitivity").append('=').append(JodaBeanUtils.toString(sensitivity));
    buf.append('}');
    return buf.toString();
  }

  //-----------------------------------------------------------------------
  /**
   * The meta-bean for {@code OvernightFutureOptionSensitivity}.
   */
  public static final class Meta extends DirectMetaBean {
    /**
     * The singleton instance of the meta-bean.
     */
    static final Meta INSTANCE = new Meta();

    /**
     * The meta-property for the {@code volatilitiesName} property.
     */
    private final MetaProperty<OvernightFutureOptionVolatilitiesName> volatilitiesName = DirectMetaProperty.ofImmutable(
        this, "volatilitiesName", OvernightFutureOptionSensitivity.class, OvernightFutureOptionVolatilitiesName.class);
    /**
     * The meta-property for the {@code expiry} property.
     */
    private final MetaProperty<Double> expiry = DirectMetaProperty.ofImmutable(
        this, "expiry", OvernightFutureOptionSensitivity.class, Double.TYPE);
    /**
     * The meta-property for the {@code fixingDate} property.
     */
    private final MetaProperty<LocalDate> fixingDate = DirectMetaProperty.ofImmutable(
        this, "fixingDate", OvernightFutureOptionSensitivity.class, LocalDate.class);
    /**
     * The meta-property for the {@code strikePrice} property.
     */
    private final MetaProperty<Double> strikePrice = DirectMetaProperty.ofImmutable(
        this, "strikePrice", OvernightFutureOptionSensitivity.class, Double.TYPE);
    /**
     * The meta-property for the {@code futurePrice} property.
     */
    private final MetaProperty<Double> futurePrice = DirectMetaProperty.ofImmutable(
        this, "futurePrice", OvernightFutureOptionSensitivity.class, Double.TYPE);
    /**
     * The meta-property for the {@code currency} property.
     */
    private final MetaProperty<Currency> currency = DirectMetaProperty.ofImmutable(
        this, "currency", OvernightFutureOptionSensitivity.class, Currency.class);
    /**
     * The meta-property for the {@code sensitivity} property.
     */
    private final MetaProperty<Double> sensitivity = DirectMetaProperty.ofImmutable(
        this, "sensitivity", OvernightFutureOptionSensitivity.class, Double.TYPE);
    /**
     * The meta-properties.
     */
    private final Map<String, MetaProperty<?>> metaPropertyMap$ = new DirectMetaPropertyMap(
        this, null,
        "volatilitiesName",
        "expiry",
        "fixingDate",
        "strikePrice",
        "futurePrice",
        "currency",
        "sensitivity");

    /**
     * Restricted constructor.
     */
    private Meta() {
    }

    @Override
    protected MetaProperty<?> metaPropertyGet(String propertyName) {
      switch (propertyName.hashCode()) {
        case 2100884654:  // volatilitiesName
          return volatilitiesName;
        case -1289159373:  // expiry
          return expiry;
        case 1255202043:  // fixingDate
          return fixingDate;
        case 50946231:  // strikePrice
          return strikePrice;
        case -518499002:  // futurePrice
          return futurePrice;
        case 575402001:  // currency
          return currency;
        case 564403871:  // sensitivity
          return sensitivity;
      }
      return super.metaPropertyGet(propertyName);
    }

    @Override
    public BeanBuilder<? extends OvernightFutureOptionSensitivity> builder() {
      return new OvernightFutureOptionSensitivity.Builder();
    }

    @Override
    public Class<? extends OvernightFutureOptionSensitivity> beanType() {
      return OvernightFutureOptionSensitivity.class;
    }

    @Override
    public Map<String, MetaProperty<?>> metaPropertyMap() {
      return metaPropertyMap$;
    }

    //-----------------------------------------------------------------------
    /**
     * The meta-property for the {@code volatilitiesName} property.
     * @return the meta-property, not null
     */
    public MetaProperty<OvernightFutureOptionVolatilitiesName> volatilitiesName() {
      return volatilitiesName;
    }

    /**
     * The meta-property for the {@code expiry} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Double> expiry() {
      return expiry;
    }

    /**
     * The meta-property for the {@code fixingDate} property.
     * @return the meta-property, not null
     */
    public MetaProperty<LocalDate> fixingDate() {
      return fixingDate;
    }

    /**
     * The meta-property for the {@code strikePrice} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Double> strikePrice() {
      return strikePrice;
    }

    /**
     * The meta-property for the {@code futurePrice} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Double> futurePrice() {
      return futurePrice;
    }

    /**
     * The meta-property for the {@code currency} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Currency> currency() {
      return currency;
    }

    /**
     * The meta-property for the {@code sensitivity} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Double> sensitivity() {
      return sensitivity;
    }

    //-----------------------------------------------------------------------
    @Override
    protected Object propertyGet(Bean bean, String propertyName, boolean quiet) {
      switch (propertyName.hashCode()) {
        case 2100884654:  // volatilitiesName
          return ((OvernightFutureOptionSensitivity) bean).getVolatilitiesName();
        case -1289159373:  // expiry
          return ((OvernightFutureOptionSensitivity) bean).getExpiry();
        case 1255202043:  // fixingDate
          return ((OvernightFutureOptionSensitivity) bean).getFixingDate();
        case 50946231:  // strikePrice
          return ((OvernightFutureOptionSensitivity) bean).getStrikePrice();
        case -518499002:  // futurePrice
          return ((OvernightFutureOptionSensitivity) bean).getFuturePrice();
        case 575402001:  // currency
          return ((OvernightFutureOptionSensitivity) bean).getCurrency();
        case 564403871:  // sensitivity
          return ((OvernightFutureOptionSensitivity) bean).getSensitivity();
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
   * The bean-builder for {@code OvernightFutureOptionSensitivity}.
   */
  private static final class Builder extends DirectPrivateBeanBuilder<OvernightFutureOptionSensitivity> {

    private OvernightFutureOptionVolatilitiesName volatilitiesName;
    private double expiry;
    private LocalDate fixingDate;
    private double strikePrice;
    private double futurePrice;
    private Currency currency;
    private double sensitivity;

    /**
     * Restricted constructor.
     */
    private Builder() {
    }

    //-----------------------------------------------------------------------
    @Override
    public Object get(String propertyName) {
      switch (propertyName.hashCode()) {
        case 2100884654:  // volatilitiesName
          return volatilitiesName;
        case -1289159373:  // expiry
          return expiry;
        case 1255202043:  // fixingDate
          return fixingDate;
        case 50946231:  // strikePrice
          return strikePrice;
        case -518499002:  // futurePrice
          return futurePrice;
        case 575402001:  // currency
          return currency;
        case 564403871:  // sensitivity
          return sensitivity;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
    }

    @Override
    public Builder set(String propertyName, Object newValue) {
      switch (propertyName.hashCode()) {
        case 2100884654:  // volatilitiesName
          this.volatilitiesName = (OvernightFutureOptionVolatilitiesName) newValue;
          break;
        case -1289159373:  // expiry
          this.expiry = (Double) newValue;
          break;
        case 1255202043:  // fixingDate
          this.fixingDate = (LocalDate) newValue;
          break;
        case 50946231:  // strikePrice
          this.strikePrice = (Double) newValue;
          break;
        case -518499002:  // futurePrice
          this.futurePrice = (Double) newValue;
          break;
        case 575402001:  // currency
          this.currency = (Currency) newValue;
          break;
        case 564403871:  // sensitivity
          this.sensitivity = (Double) newValue;
          break;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
      return this;
    }

    @Override
    public OvernightFutureOptionSensitivity build() {
      return new OvernightFutureOptionSensitivity(
          volatilitiesName,
          expiry,
          fixingDate,
          strikePrice,
          futurePrice,
          currency,
          sensitivity);
    }

    //-----------------------------------------------------------------------
    @Override
    public String toString() {
      StringBuilder buf = new StringBuilder(256);
      buf.append("OvernightFutureOptionSensitivity.Builder{");
      buf.append("volatilitiesName").append('=').append(JodaBeanUtils.toString(volatilitiesName)).append(',').append(' ');
      buf.append("expiry").append('=').append(JodaBeanUtils.toString(expiry)).append(',').append(' ');
      buf.append("fixingDate").append('=').append(JodaBeanUtils.toString(fixingDate)).append(',').append(' ');
      buf.append("strikePrice").append('=').append(JodaBeanUtils.toString(strikePrice)).append(',').append(' ');
      buf.append("futurePrice").append('=').append(JodaBeanUtils.toString(futurePrice)).append(',').append(' ');
      buf.append("currency").append('=').append(JodaBeanUtils.toString(currency)).append(',').append(' ');
      buf.append("sensitivity").append('=').append(JodaBeanUtils.toString(sensitivity));
      buf.append('}');
      return buf.toString();
    }

  }

  //-------------------------- AUTOGENERATED END --------------------------
}
