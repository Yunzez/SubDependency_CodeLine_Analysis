package org.junit.rules;

import java.io.File;
import java.io.IOException;

public class TemporaryFolder extends ExternalResource {
  private final File parentFolder;
  
  private File folder;
  
  public TemporaryFolder() {
    this(null);
  }
  
  public TemporaryFolder(File parentFolder) {
    this.parentFolder = parentFolder;
  }
  
  protected void before() throws Throwable {
    create();
  }
  
  protected void after() {
    delete();
  }
  
  public void create() throws IOException {
    this.folder = createTemporaryFolderIn(this.parentFolder);
  }
  
  public File newFile(String fileName) throws IOException {
    File file = new File(getRoot(), fileName);
    if (!file.createNewFile())
      throw new IOException("a file with the name '" + fileName + "' already exists in the test folder"); 
    return file;
  }
  
  public File newFile() throws IOException {
    return File.createTempFile("junit", null, getRoot());
  }
  
  public File newFolder(String folder) throws IOException {
    return newFolder(new String[] { folder });
  }
  
  public File newFolder(String... folderNames) throws IOException {
    File file = getRoot();
    for (int i = 0; i < folderNames.length; i++) {
      String folderName = folderNames[i];
      file = new File(file, folderName);
      if (!file.mkdir() && isLastElementInArray(i, folderNames))
        throw new IOException("a folder with the name '" + folderName + "' already exists"); 
    } 
    return file;
  }
  
  private boolean isLastElementInArray(int index, String[] array) {
    return (index == array.length - 1);
  }
  
  public File newFolder() throws IOException {
    return createTemporaryFolderIn(getRoot());
  }
  
  private File createTemporaryFolderIn(File parentFolder) throws IOException {
    File createdFolder = File.createTempFile("junit", "", parentFolder);
    createdFolder.delete();
    createdFolder.mkdir();
    return createdFolder;
  }
  
  public File getRoot() {
    if (this.folder == null)
      throw new IllegalStateException("the temporary folder has not yet been created"); 
    return this.folder;
  }
  
  public void delete() {
    if (this.folder != null)
      recursiveDelete(this.folder); 
  }
  
  private void recursiveDelete(File file) {
    File[] files = file.listFiles();
    if (files != null)
      for (File each : files)
        recursiveDelete(each);  
    file.delete();
  }
}
