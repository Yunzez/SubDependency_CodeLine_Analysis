package junit.framework;

public class ComparisonCompactor {
  private static final String ELLIPSIS = "...";
  
  private static final String DELTA_END = "]";
  
  private static final String DELTA_START = "[";
  
  private int fContextLength;
  
  private String fExpected;
  
  private String fActual;
  
  private int fPrefix;
  
  private int fSuffix;
  
  public ComparisonCompactor(int contextLength, String expected, String actual) {
    this.fContextLength = contextLength;
    this.fExpected = expected;
    this.fActual = actual;
  }
  
  public String compact(String message) {
    if (this.fExpected == null || this.fActual == null || areStringsEqual())
      return Assert.format(message, this.fExpected, this.fActual); 
    findCommonPrefix();
    findCommonSuffix();
    String expected = compactString(this.fExpected);
    String actual = compactString(this.fActual);
    return Assert.format(message, expected, actual);
  }
  
  private String compactString(String source) {
    String result = "[" + source.substring(this.fPrefix, source.length() - this.fSuffix + 1) + "]";
    if (this.fPrefix > 0)
      result = computeCommonPrefix() + result; 
    if (this.fSuffix > 0)
      result = result + computeCommonSuffix(); 
    return result;
  }
  
  private void findCommonPrefix() {
    this.fPrefix = 0;
    int end = Math.min(this.fExpected.length(), this.fActual.length());
    for (; this.fPrefix < end && 
      this.fExpected.charAt(this.fPrefix) == this.fActual.charAt(this.fPrefix); this.fPrefix++);
  }
  
  private void findCommonSuffix() {
    int expectedSuffix = this.fExpected.length() - 1;
    int actualSuffix = this.fActual.length() - 1;
    while (actualSuffix >= this.fPrefix && expectedSuffix >= this.fPrefix && 
      this.fExpected.charAt(expectedSuffix) == this.fActual.charAt(actualSuffix)) {
      actualSuffix--;
      expectedSuffix--;
    } 
    this.fSuffix = this.fExpected.length() - expectedSuffix;
  }
  
  private String computeCommonPrefix() {
    return ((this.fPrefix > this.fContextLength) ? "..." : "") + this.fExpected.substring(Math.max(0, this.fPrefix - this.fContextLength), this.fPrefix);
  }
  
  private String computeCommonSuffix() {
    int end = Math.min(this.fExpected.length() - this.fSuffix + 1 + this.fContextLength, this.fExpected.length());
    return this.fExpected.substring(this.fExpected.length() - this.fSuffix + 1, end) + ((this.fExpected.length() - this.fSuffix + 1 < this.fExpected.length() - this.fContextLength) ? "..." : "");
  }
  
  private boolean areStringsEqual() {
    return this.fExpected.equals(this.fActual);
  }
}
