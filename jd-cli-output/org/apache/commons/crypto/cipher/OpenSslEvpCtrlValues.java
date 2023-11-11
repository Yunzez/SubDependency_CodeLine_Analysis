package org.apache.commons.crypto.cipher;

enum OpenSslEvpCtrlValues {
  INIT(0),
  SET_KEY_LENGTH(1),
  GET_RC2_KEY_BITS(2),
  SET_RC2_KEY_BITS(3),
  GET_RC5_ROUNDS(4),
  SET_RC5_ROUNDS(5),
  RAND_KEY(6),
  PBE_PRF_NID(7),
  COPY(8),
  AEAD_SET_IVLEN(9),
  AEAD_GET_TAG(16),
  AEAD_SET_TAG(17),
  AEAD_SET_IV_FIXED(18),
  GCM_IV_GEN(19),
  CCM_SET_L(20),
  CCM_SET_MSGLEN(21);
  
  private final int value;
  
  OpenSslEvpCtrlValues(int value) {
    this.value = value;
  }
  
  int getValue() {
    return this.value;
  }
}
