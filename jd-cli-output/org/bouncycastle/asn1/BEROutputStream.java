package org.bouncycastle.asn1;

import java.io.OutputStream;

class BEROutputStream extends ASN1OutputStream {
  BEROutputStream(OutputStream paramOutputStream) {
    super(paramOutputStream);
  }
}
