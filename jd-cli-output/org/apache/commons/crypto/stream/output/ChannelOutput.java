package org.apache.commons.crypto.stream.output;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

public class ChannelOutput implements Output {
  private final WritableByteChannel channel;
  
  public ChannelOutput(WritableByteChannel channel) {
    this.channel = channel;
  }
  
  public int write(ByteBuffer src) throws IOException {
    return this.channel.write(src);
  }
  
  public void flush() throws IOException {}
  
  public void close() throws IOException {
    this.channel.close();
  }
}
