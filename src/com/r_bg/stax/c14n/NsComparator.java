package com.r_bg.stax.c14n;

import java.util.Comparator;

import javax.xml.stream.XMLStreamReader;

class NsCompartor implements Comparator {
	XMLStreamReader in;
	public NsCompartor(XMLStreamReader in) {
		this.in=in;
	}
	public int compare(Object arg0, Object arg1) {
		int first=((Integer)arg0).intValue();
		int second=((Integer)arg1).intValue();
		String uri1=in.getNamespacePrefix(first);
		String uri2=in.getNamespacePrefix(second);
		return uri1.compareTo(uri2);						
	}	
}