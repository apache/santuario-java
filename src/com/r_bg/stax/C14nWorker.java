package com.r_bg.stax;

import java.io.OutputStream;

import javax.xml.stream.XMLStreamReader;

import com.r_bg.stax.c14n.C14n;

public class C14nWorker implements StaxWorker {
	DigestResultListener re;
	C14n c14n;
	public C14nWorker(DigestResultListener re, OutputStream os, boolean withComments) {
		c14n=new C14n(new com.r_bg.stax.c14n.AttributeHandleExclusive(),os, withComments);
		this.re=re;
	}

	public StaxWorker read(XMLStreamReader reader) {
		c14n.accept(reader);
		return null;
	}

	public StaxWatcher remove() {
		re.setResult(null);
		return null;
	}
}
