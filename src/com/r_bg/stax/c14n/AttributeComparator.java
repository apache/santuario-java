package com.r_bg.stax.c14n;

import java.util.Comparator;

import javax.xml.stream.XMLStreamReader;

class AttributeCompartor implements Comparator {
	XMLStreamReader in;
	public AttributeCompartor(XMLStreamReader in) {
		this.in=in;
	}
	public int compare(Object arg0, Object arg1) {
		int first=((Integer)arg0).intValue();
		int second=((Integer)arg1).intValue();
		String uri1=in.getAttributeNamespace(first);
		String uri2=in.getAttributeNamespace(second);
		if (uri1==null) {			
			return (uri2!=null )? 1 : 
						in.getAttributeLocalName(first).compareTo(in.getAttributeLocalName(second));
		}
		if (uri2==null) {
			return -1;
		}			
		int result=uri1.compareTo(uri2);		
		return  (result!=0) ? result :in.getAttributeLocalName(first).compareTo(in.getAttributeLocalName(second));				
	}	
}
