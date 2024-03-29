/*
 * Copyright (C) 2015 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.loader.csv;

import static com.opengamma.strata.collect.TestHelper.coverPrivateConstructor;
import static com.opengamma.strata.collect.TestHelper.date;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.time.LocalDate;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.opengamma.strata.basics.currency.Currency;
import com.opengamma.strata.basics.currency.FxRate;
import com.opengamma.strata.collect.io.ResourceLocator;
import com.opengamma.strata.collect.result.ParseFailureException;
import com.opengamma.strata.data.FxRateId;

/**
 * Test {@link FxRatesCsvLoader}.
 */
public class FxRatesCsvLoaderTest {

  private static final FxRateId EUR_USD_ID = FxRateId.of(Currency.EUR, Currency.USD);
  private static final FxRateId GBP_USD_ID = FxRateId.of(Currency.GBP, Currency.USD);
  private static final FxRateId EUR_CHF_ID = FxRateId.of(Currency.EUR, Currency.CHF);
  private static final LocalDate DATE1 = date(2014, 1, 22);
  private static final LocalDate DATE2 = date(2014, 1, 23);

  private static final ResourceLocator RATES_1 =
      ResourceLocator.of("classpath:com/opengamma/strata/loader/csv/fx-rates-1.csv");
  private static final ResourceLocator RATES_2 =
      ResourceLocator.of("classpath:com/opengamma/strata/loader/csv/fx-rates-2.csv");
  private static final ResourceLocator RATES_INVALID_DATE =
      ResourceLocator.of("classpath:com/opengamma/strata/loader/csv/fx-rates-invalid-date.csv");
  private static final ResourceLocator RATES_INVALID_DUPLICATE =
      ResourceLocator.of("classpath:com/opengamma/strata/loader/csv/fx-rates-invalid-duplicate.csv");

  //-------------------------------------------------------------------------
  @Test
  public void test_load_oneDate_file1_date1() {
    Map<FxRateId, FxRate> map = FxRatesCsvLoader.load(DATE1, RATES_1);
    assertThat(map).hasSize(2);
    assertFile1Date1(map);
  }

  @Test
  public void test_load_oneDate_file1_date2() {
    Map<FxRateId, FxRate> map = FxRatesCsvLoader.load(DATE2, ImmutableList.of(RATES_1));
    assertThat(map).hasSize(2);
    assertFile1Date2(map);
  }

  @Test
  public void test_load_oneDate_file1file2_date1() {
    Map<FxRateId, FxRate> map = FxRatesCsvLoader.load(DATE1, ImmutableList.of(RATES_1, RATES_2));
    assertThat(map).hasSize(3);
    assertFile1Date1(map);
    assertFile2Date1(map);
  }

  @Test
  public void test_load_oneDate_invalidDate() {
    assertThatExceptionOfType(ParseFailureException.class)
        .isThrownBy(() -> FxRatesCsvLoader.load(date(2015, 10, 2), RATES_INVALID_DATE))
        .withMessageStartingWith("Error parsing CSV file 'fx-rates-invalid-date.csv': Unable to parse date");
  }

  @Test
  public void test_invalidDuplicate() {
    assertThatExceptionOfType(ParseFailureException.class)
        .isThrownBy(() -> FxRatesCsvLoader.load(DATE1, RATES_INVALID_DUPLICATE));
  }

  @Test
  public void test_load_dateSet_file1_date1() {
    Map<LocalDate, ImmutableMap<FxRateId, FxRate>> map = FxRatesCsvLoader.load(ImmutableSet.of(DATE1, DATE2), RATES_1);
    assertThat(map).hasSize(2);
    assertFile1Date1(map.get(DATE1));
    assertFile1Date2(map.get(DATE2));
  }

  @Test
  public void test_load_alLDates_file1_date1() {
    Map<LocalDate, ImmutableMap<FxRateId, FxRate>> map = FxRatesCsvLoader.loadAllDates(RATES_1);
    assertThat(map).hasSize(2);
    assertFile1Date1(map.get(DATE1));
    assertFile1Date2(map.get(DATE2));
  }

  //-------------------------------------------------------------------------
  private void assertFile1Date1(Map<FxRateId, FxRate> map) {
    assertThat(map.containsKey(EUR_USD_ID)).isTrue();
    assertThat(map.containsKey(GBP_USD_ID)).isTrue();
    assertThat(map.get(EUR_USD_ID)).isEqualTo(FxRate.of(Currency.EUR, Currency.USD, 1.11));
    assertThat(map.get(GBP_USD_ID)).isEqualTo(FxRate.of(Currency.GBP, Currency.USD, 1.51));
  }

  private void assertFile1Date2(Map<FxRateId, FxRate> map) {
    assertThat(map.containsKey(EUR_USD_ID)).isTrue();
    assertThat(map.containsKey(GBP_USD_ID)).isTrue();
    assertThat(map.get(EUR_USD_ID)).isEqualTo(FxRate.of(Currency.EUR, Currency.USD, 1.12));
    assertThat(map.get(GBP_USD_ID)).isEqualTo(FxRate.of(Currency.GBP, Currency.USD, 1.52));
  }

  private void assertFile2Date1(Map<FxRateId, FxRate> map) {
    assertThat(map.containsKey(EUR_CHF_ID)).isTrue();
    assertThat(map.get(EUR_CHF_ID)).isEqualTo(FxRate.of(Currency.EUR, Currency.CHF, 1.09));
  }

  //-------------------------------------------------------------------------
  @Test
  public void coverage() {
    coverPrivateConstructor(FxRatesCsvLoader.class);
  }

}
