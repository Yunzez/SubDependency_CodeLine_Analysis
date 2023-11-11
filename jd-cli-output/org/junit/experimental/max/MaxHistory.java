package org.junit.experimental.max;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import org.junit.runner.Description;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

public class MaxHistory implements Serializable {
  private static final long serialVersionUID = 1L;
  
  public static MaxHistory forFolder(File file) {
    if (file.exists())
      try {
        return readHistory(file);
      } catch (CouldNotReadCoreException e) {
        e.printStackTrace();
        file.delete();
      }  
    return new MaxHistory(file);
  }
  
  private static MaxHistory readHistory(File storedResults) throws CouldNotReadCoreException {
    try {
      FileInputStream file = new FileInputStream(storedResults);
      try {
        ObjectInputStream stream = new ObjectInputStream(file);
      } finally {
        file.close();
      } 
    } catch (Exception e) {
      throw new CouldNotReadCoreException(e);
    } 
  }
  
  private final Map<String, Long> fDurations = new HashMap<String, Long>();
  
  private final Map<String, Long> fFailureTimestamps = new HashMap<String, Long>();
  
  private final File fHistoryStore;
  
  private MaxHistory(File storedResults) {
    this.fHistoryStore = storedResults;
  }
  
  private void save() throws IOException {
    ObjectOutputStream stream = new ObjectOutputStream(new FileOutputStream(this.fHistoryStore));
    stream.writeObject(this);
    stream.close();
  }
  
  Long getFailureTimestamp(Description key) {
    return this.fFailureTimestamps.get(key.toString());
  }
  
  void putTestFailureTimestamp(Description key, long end) {
    this.fFailureTimestamps.put(key.toString(), Long.valueOf(end));
  }
  
  boolean isNewTest(Description key) {
    return !this.fDurations.containsKey(key.toString());
  }
  
  Long getTestDuration(Description key) {
    return this.fDurations.get(key.toString());
  }
  
  void putTestDuration(Description description, long duration) {
    this.fDurations.put(description.toString(), Long.valueOf(duration));
  }
  
  private final class RememberingListener extends RunListener {
    private long overallStart = System.currentTimeMillis();
    
    private Map<Description, Long> starts = new HashMap<Description, Long>();
    
    public void testStarted(Description description) throws Exception {
      this.starts.put(description, Long.valueOf(System.nanoTime()));
    }
    
    public void testFinished(Description description) throws Exception {
      long end = System.nanoTime();
      long start = ((Long)this.starts.get(description)).longValue();
      MaxHistory.this.putTestDuration(description, end - start);
    }
    
    public void testFailure(Failure failure) throws Exception {
      MaxHistory.this.putTestFailureTimestamp(failure.getDescription(), this.overallStart);
    }
    
    public void testRunFinished(Result result) throws Exception {
      MaxHistory.this.save();
    }
    
    private RememberingListener() {}
  }
  
  private class TestComparator implements Comparator<Description> {
    private TestComparator() {}
    
    public int compare(Description o1, Description o2) {
      if (MaxHistory.this.isNewTest(o1))
        return -1; 
      if (MaxHistory.this.isNewTest(o2))
        return 1; 
      int result = getFailure(o2).compareTo(getFailure(o1));
      return (result != 0) ? result : MaxHistory.this.getTestDuration(o1).compareTo(MaxHistory.this.getTestDuration(o2));
    }
    
    private Long getFailure(Description key) {
      Long result = MaxHistory.this.getFailureTimestamp(key);
      if (result == null)
        return Long.valueOf(0L); 
      return result;
    }
  }
  
  public RunListener listener() {
    return new RememberingListener();
  }
  
  public Comparator<Description> testComparator() {
    return new TestComparator();
  }
}
