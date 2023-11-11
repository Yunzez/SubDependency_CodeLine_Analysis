package org.bouncycastle.crypto.util;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AlphabetMapper;

public class BasicAlphabetMapper implements AlphabetMapper {
  private Map<Character, Integer> indexMap = new HashMap<Character, Integer>();
  
  private Map<Integer, Character> charMap = new HashMap<Integer, Character>();
  
  public BasicAlphabetMapper(String paramString) {
    this(paramString.toCharArray());
  }
  
  public BasicAlphabetMapper(char[] paramArrayOfchar) {
    for (byte b = 0; b != paramArrayOfchar.length; b++) {
      if (this.indexMap.containsKey(Character.valueOf(paramArrayOfchar[b])))
        throw new IllegalArgumentException("duplicate key detected in alphabet: " + paramArrayOfchar[b]); 
      this.indexMap.put(Character.valueOf(paramArrayOfchar[b]), Integer.valueOf(b));
      this.charMap.put(Integer.valueOf(b), Character.valueOf(paramArrayOfchar[b]));
    } 
  }
  
  public int getRadix() {
    return this.indexMap.size();
  }
  
  public byte[] convertToIndexes(char[] paramArrayOfchar) {
    byte[] arrayOfByte;
    if (this.indexMap.size() <= 256) {
      arrayOfByte = new byte[paramArrayOfchar.length];
      for (byte b = 0; b != paramArrayOfchar.length; b++)
        arrayOfByte[b] = ((Integer)this.indexMap.get(Character.valueOf(paramArrayOfchar[b]))).byteValue(); 
    } else {
      arrayOfByte = new byte[paramArrayOfchar.length * 2];
      for (byte b = 0; b != paramArrayOfchar.length; b++) {
        int i = ((Integer)this.indexMap.get(Character.valueOf(paramArrayOfchar[b]))).intValue();
        arrayOfByte[b * 2] = (byte)(i >> 8 & 0xFF);
        arrayOfByte[b * 2 + 1] = (byte)(i & 0xFF);
      } 
    } 
    return arrayOfByte;
  }
  
  public char[] convertToChars(byte[] paramArrayOfbyte) {
    char[] arrayOfChar;
    if (this.charMap.size() <= 256) {
      arrayOfChar = new char[paramArrayOfbyte.length];
      for (byte b = 0; b != paramArrayOfbyte.length; b++)
        arrayOfChar[b] = ((Character)this.charMap.get(Integer.valueOf(paramArrayOfbyte[b] & 0xFF))).charValue(); 
    } else {
      if ((paramArrayOfbyte.length & 0x1) != 0)
        throw new IllegalArgumentException("two byte radix and input string odd length"); 
      arrayOfChar = new char[paramArrayOfbyte.length / 2];
      for (byte b = 0; b != paramArrayOfbyte.length; b += 2)
        arrayOfChar[b / 2] = ((Character)this.charMap.get(Integer.valueOf(paramArrayOfbyte[b] << 8 & 0xFF00 | paramArrayOfbyte[b + 1] & 0xFF))).charValue(); 
    } 
    return arrayOfChar;
  }
}
