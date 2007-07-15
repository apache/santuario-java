package com.r_bg.stax;

import java.security.Key;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLStreamReader;

public class StaxValidateContext implements XMLValidateContext {	
	XMLStreamReader reader;
	int signatureNumber=0;
	private StaxSignatureVerificator sig;
	Key key;
	public static StaxValidateContext createEnvolopedValidator(Key key, XMLStreamReader reader) {		
		return new StaxValidateContext(key,reader);
	}
	public void setSignatureNumber(int number) {
		signatureNumber=number;
	}
	
	protected StaxValidateContext(Key key,XMLStreamReader reader) {
		this.key=key;
		this.reader=reader;		
	}
	
	public String getBaseURI() {
		// TODO Auto-generated method stub
		return null;
	}

	public void setBaseURI(String baseURI) {
		// TODO Auto-generated method stub

	}

	public KeySelector getKeySelector() {
		// TODO Auto-generated method stub
		return null;
	}

	public void setKeySelector(KeySelector ks) {
		// TODO Auto-generated method stub

	}

	public URIDereferencer getURIDereferencer() {
		// TODO Auto-generated method stub
		return null;
	}

	public void setURIDereferencer(URIDereferencer dereferencer) {
		// TODO Auto-generated method stub

	}

	public String getNamespacePrefix(String namespaceURI, String defaultPrefix) {
		// TODO Auto-generated method stub
		return null;
	}

	public String putNamespacePrefix(String namespaceURI, String prefix) {
		// TODO Auto-generated method stub
		return null;
	}

	public String getDefaultNamespacePrefix() {
		// TODO Auto-generated method stub
		return null;
	}

	public void setDefaultNamespacePrefix(String defaultPrefix) {
		// TODO Auto-generated method stub

	}

	public Object setProperty(String name, Object value) {
		// TODO Auto-generated method stub
		return null;
	}

	public Object getProperty(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	public Object get(Object key) {
		// TODO Auto-generated method stub
		return null;
	}

	public Object put(Object key, Object value) {
		// TODO Auto-generated method stub
		return null;
	}

	public StreamFilter getStreamReader() {
		sig = new StaxSignatureVerificator();
		return sig;
	}

	protected XMLSignature getSignature() {
		return sig.signatures.get(signatureNumber);
	}

}
