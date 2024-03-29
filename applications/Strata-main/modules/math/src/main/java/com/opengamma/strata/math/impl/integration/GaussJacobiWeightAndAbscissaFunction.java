/*
 * Copyright (C) 2009 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.strata.math.impl.integration;

import java.util.function.DoubleUnaryOperator;

import org.apache.commons.math3.util.CombinatoricsUtils;

import com.opengamma.strata.collect.ArgChecker;
import com.opengamma.strata.collect.tuple.Pair;
import com.opengamma.strata.math.impl.function.DoubleFunction1D;
import com.opengamma.strata.math.impl.function.special.GammaFunction;
import com.opengamma.strata.math.impl.function.special.JacobiPolynomialFunction;
import com.opengamma.strata.math.impl.rootfinding.NewtonRaphsonSingleRootFinder;

/**
 * Class that generates weights and abscissas for Gauss-Jacobi quadrature. The
 * weights $w_i$ are given by:
 * $$
 * \begin{align*}
 * w_i = \frac{2^{\alpha + \beta}(2n + \alpha + \beta)\Gamma(\alpha + n)\Gamma(\beta + n)}
 * {n!\Gamma(n + \alpha + \beta + 1)J_i'(x_i) J_{i - 1}}
 * \end{align*}
 * $$
 * where $x_i$ is the $i^{th}$ root of the orthogonal polynomial, $J_i$ is the
 * $i^{th}$ polynomial and $J_i'$ is the first derivative of the $i^{th}$
 * polynomial. The orthogonal polynomial is generated by
 * {@link JacobiPolynomialFunction}.
 */
public class GaussJacobiWeightAndAbscissaFunction implements QuadratureWeightAndAbscissaFunction {

  private static final JacobiPolynomialFunction JACOBI = new JacobiPolynomialFunction();
  private static final NewtonRaphsonSingleRootFinder ROOT_FINDER = new NewtonRaphsonSingleRootFinder(1e-12);
  private static final DoubleUnaryOperator GAMMA_FUNCTION = new GammaFunction();
  private final double _alpha;
  private final double _beta;
  private final double _c;

  /**
   * Creates an instance.
   * Sets $\alpha = 0$ and $\beta = 0$
   */
  public GaussJacobiWeightAndAbscissaFunction() {
    this(0, 0);
  }

  /**
   * Creates an instance.
   * @param alpha The value of $\alpha$ to use when generating the polynomials
   * @param beta The value of $\beta$ to use when generating the polynomials
   */
  public GaussJacobiWeightAndAbscissaFunction(double alpha, double beta) {
    super();
    _alpha = alpha;
    _beta = beta;
    _c = _alpha + _beta;
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public GaussianQuadratureData generate(int n) {
    ArgChecker.isTrue(n > 0, "n > 0");
    Pair<DoubleFunction1D, DoubleFunction1D>[] polynomials = JACOBI.getPolynomialsAndFirstDerivative(n, _alpha, _beta);
    Pair<DoubleFunction1D, DoubleFunction1D> pair = polynomials[n];
    DoubleFunction1D previous = polynomials[n - 1].getFirst();
    DoubleFunction1D function = pair.getFirst();
    DoubleFunction1D derivative = pair.getSecond();
    double[] x = new double[n];
    double[] w = new double[n];
    double root = 0;
    for (int i = 0; i < n; i++) {
      double d = 2 * n + _c;
      root = getInitialRootGuess(root, i, n, x);
      root = ROOT_FINDER.getRoot(function, derivative, root);
      x[i] = root;
      w[i] =
          GAMMA_FUNCTION.applyAsDouble(_alpha + n) * GAMMA_FUNCTION.applyAsDouble(_beta + n) /
              CombinatoricsUtils.factorialDouble(n) / GAMMA_FUNCTION.applyAsDouble(n + _c + 1) * d *
              Math.pow(2, _c)
              / (derivative.applyAsDouble(root) * previous.applyAsDouble(root));
    }
    return new GaussianQuadratureData(x, w);
  }

  private double getInitialRootGuess(double previousRoot, int i, int n, double[] x) {
    if (i == 0) {
      double a = _alpha / n;
      double b = _beta / n;
      double x1 = (1 + _alpha) * (2.78 / (4 + n * n) + 0.768 * a / n);
      double x2 = 1 + 1.48 * a + 0.96 * b + 0.452 * a * a + 0.83 * a * b;
      return 1 - x1 / x2;
    }
    if (i == 1) {
      double x1 = (4.1 + _alpha) / ((1 + _alpha) * (1 + 0.156 * _alpha));
      double x2 = 1 + 0.06 * (n - 8) * (1 + 0.12 * _alpha) / n;
      double x3 = 1 + 0.012 * _beta * (1 + 0.25 * Math.abs(_alpha)) / n;
      return previousRoot - (1 - previousRoot) * x1 * x2 * x3;
    }
    if (i == 2) {
      double x1 = (1.67 + 0.28 * _alpha) / (1 + 0.37 * _alpha);
      double x2 = 1 + 0.22 * (n - 8) / n;
      double x3 = 1 + 8 * _beta / ((6.28 + _beta) * n * n);
      return previousRoot - (x[0] - previousRoot) * x1 * x2 * x3;
    }
    if (i == n - 2) {
      double x1 = (1 + 0.235 * _beta) / (0.766 + 0.119 * _beta);
      double x2 = 1. / (1 + 0.639 * (n - 4.) / (1 + 0.71 * (n - 4.)));
      double x3 = 1. / (1 + 20 * _alpha / ((7.5 + _alpha) * n * n));
      return previousRoot + (previousRoot - x[n - 4]) * x1 * x2 * x3;
    }
    if (i == n - 1) {
      double x1 = (1 + 0.37 * _beta) / (1.67 + 0.28 * _beta);
      double x2 = 1. / (1 + 0.22 * (n - 8.) / n);
      double x3 = 1. / (1 + 8. * _alpha / ((6.28 + _alpha) * n * n));
      return previousRoot + (previousRoot - x[n - 3]) * x1 * x2 * x3;
    }
    return 3. * x[i - 1] - 3. * x[i - 2] + x[i - 3];
  }

}
