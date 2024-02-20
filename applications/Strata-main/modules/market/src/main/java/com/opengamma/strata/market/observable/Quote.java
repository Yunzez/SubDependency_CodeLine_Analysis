/*
 * Copyright (C) 2017 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.market.observable;

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

/**
 * A quoted value for a given security, such as an equity or future.
 * <p>
 * This represents a single numeric value of a given security, such as the mid point between the buy/sell.
 * The {@link QuoteId} specifies the security, the type of price and the price source.
 * <p>
 * This class is immutable and thread-safe.
 */
@BeanDefinition(builderScope = "private")
public final class Quote implements ImmutableBean {

  /**
   * The identifier of the quoted value.
   */
  @PropertyDefinition(validate = "notNull")
  private final QuoteId quoteId;
  /**
   * The value that was quoted.
   */
  @PropertyDefinition(validate = "notNull")
  private final double value;

  //-------------------------------------------------------------------------
  /**
   * Obtains an instance from the quote identifier and value.
   *
   * @param quoteId  the quote identifier
   * @param value  the value for the given quote
   * @return the quote instance for the given values
   */
  public static Quote of(QuoteId quoteId, double value) {
    return new Quote(quoteId, value);
  }

  //------------------------- AUTOGENERATED START -------------------------
  /**
   * The meta-bean for {@code Quote}.
   * @return the meta-bean, not null
   */
  public static Quote.Meta meta() {
    return Quote.Meta.INSTANCE;
  }

  static {
    MetaBean.register(Quote.Meta.INSTANCE);
  }

  private Quote(
      QuoteId quoteId,
      double value) {
    JodaBeanUtils.notNull(quoteId, "quoteId");
    JodaBeanUtils.notNull(value, "value");
    this.quoteId = quoteId;
    this.value = value;
  }

  @Override
  public Quote.Meta metaBean() {
    return Quote.Meta.INSTANCE;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the identifier of the quoted value.
   * @return the value of the property, not null
   */
  public QuoteId getQuoteId() {
    return quoteId;
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the value that was quoted.
   * @return the value of the property, not null
   */
  public double getValue() {
    return value;
  }

  //-----------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      Quote other = (Quote) obj;
      return JodaBeanUtils.equal(quoteId, other.quoteId) &&
          JodaBeanUtils.equal(value, other.value);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = getClass().hashCode();
    hash = hash * 31 + JodaBeanUtils.hashCode(quoteId);
    hash = hash * 31 + JodaBeanUtils.hashCode(value);
    return hash;
  }

  @Override
  public String toString() {
    StringBuilder buf = new StringBuilder(96);
    buf.append("Quote{");
    buf.append("quoteId").append('=').append(JodaBeanUtils.toString(quoteId)).append(',').append(' ');
    buf.append("value").append('=').append(JodaBeanUtils.toString(value));
    buf.append('}');
    return buf.toString();
  }

  //-----------------------------------------------------------------------
  /**
   * The meta-bean for {@code Quote}.
   */
  public static final class Meta extends DirectMetaBean {
    /**
     * The singleton instance of the meta-bean.
     */
    static final Meta INSTANCE = new Meta();

    /**
     * The meta-property for the {@code quoteId} property.
     */
    private final MetaProperty<QuoteId> quoteId = DirectMetaProperty.ofImmutable(
        this, "quoteId", Quote.class, QuoteId.class);
    /**
     * The meta-property for the {@code value} property.
     */
    private final MetaProperty<Double> value = DirectMetaProperty.ofImmutable(
        this, "value", Quote.class, Double.TYPE);
    /**
     * The meta-properties.
     */
    private final Map<String, MetaProperty<?>> metaPropertyMap$ = new DirectMetaPropertyMap(
        this, null,
        "quoteId",
        "value");

    /**
     * Restricted constructor.
     */
    private Meta() {
    }

    @Override
    protected MetaProperty<?> metaPropertyGet(String propertyName) {
      switch (propertyName.hashCode()) {
        case 664377527:  // quoteId
          return quoteId;
        case 111972721:  // value
          return value;
      }
      return super.metaPropertyGet(propertyName);
    }

    @Override
    public BeanBuilder<? extends Quote> builder() {
      return new Quote.Builder();
    }

    @Override
    public Class<? extends Quote> beanType() {
      return Quote.class;
    }

    @Override
    public Map<String, MetaProperty<?>> metaPropertyMap() {
      return metaPropertyMap$;
    }

    //-----------------------------------------------------------------------
    /**
     * The meta-property for the {@code quoteId} property.
     * @return the meta-property, not null
     */
    public MetaProperty<QuoteId> quoteId() {
      return quoteId;
    }

    /**
     * The meta-property for the {@code value} property.
     * @return the meta-property, not null
     */
    public MetaProperty<Double> value() {
      return value;
    }

    //-----------------------------------------------------------------------
    @Override
    protected Object propertyGet(Bean bean, String propertyName, boolean quiet) {
      switch (propertyName.hashCode()) {
        case 664377527:  // quoteId
          return ((Quote) bean).getQuoteId();
        case 111972721:  // value
          return ((Quote) bean).getValue();
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
   * The bean-builder for {@code Quote}.
   */
  private static final class Builder extends DirectPrivateBeanBuilder<Quote> {

    private QuoteId quoteId;
    private double value;

    /**
     * Restricted constructor.
     */
    private Builder() {
    }

    //-----------------------------------------------------------------------
    @Override
    public Object get(String propertyName) {
      switch (propertyName.hashCode()) {
        case 664377527:  // quoteId
          return quoteId;
        case 111972721:  // value
          return value;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
    }

    @Override
    public Builder set(String propertyName, Object newValue) {
      switch (propertyName.hashCode()) {
        case 664377527:  // quoteId
          this.quoteId = (QuoteId) newValue;
          break;
        case 111972721:  // value
          this.value = (Double) newValue;
          break;
        default:
          throw new NoSuchElementException("Unknown property: " + propertyName);
      }
      return this;
    }

    @Override
    public Quote build() {
      return new Quote(
          quoteId,
          value);
    }

    //-----------------------------------------------------------------------
    @Override
    public String toString() {
      StringBuilder buf = new StringBuilder(96);
      buf.append("Quote.Builder{");
      buf.append("quoteId").append('=').append(JodaBeanUtils.toString(quoteId)).append(',').append(' ');
      buf.append("value").append('=').append(JodaBeanUtils.toString(value));
      buf.append('}');
      return buf.toString();
    }

  }

  //-------------------------- AUTOGENERATED END --------------------------
}
