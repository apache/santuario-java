package com.r_bg.stax.c14n;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import javax.xml.namespace.NamespaceContext;
import javax.xml.stream.XMLStreamReader;

public class AttributeHandleExclusive implements C14nAttributeHandler {
	static final byte[] EQ={'=','"'};
	static final byte[] XMLNS={' ','x','m','l','n','s'};
	public void handleAttributes(XMLStreamReader in,StaxC14nHelper nsD,OutputStream os) throws IOException{
		SortedSet args=new TreeSet(new AttributeCompartor(in));
		SortedSet nss=new TreeSet();
		Set prefixes=new HashSet();		
		int length;
		length=in.getAttributeCount();
		for (int i=0;i<length;i++) {
			args.add(new Integer(i));
			String prefix=in.getAttributePrefix(i);
			if (prefix!=null)
				prefixes.add(prefix);
		}		
		prefixes.add(in.getPrefix()==null? "" : in.getPrefix());
		Iterator it=prefixes.iterator();
		NamespaceContext nc=in.getNamespaceContext();
		while (it.hasNext()) {
			String prefix=(String)it.next();
			String nsDef=nc.getNamespaceURI(prefix);
			if (nsDef==null)
				nsDef="";
			if (!nsD.hasBeenRender(prefix,nsDef))
				nss.add(prefix);
		}
		it=nss.iterator();
		while (it.hasNext()) {			
			String realPrefix=(String) it.next();
			String prefix=realPrefix;
			os.write(XMLNS);
			if (prefix!="") {
				os.write(':');
				os.write(prefix.getBytes());				
			} 			
			os.write(EQ);
			String nsDef=nc.getNamespaceURI(realPrefix);
			if (nsDef==null) nsDef="";
			os.write(nsDef.getBytes());
			os.write('\"');;
		}
		
		it=args.iterator();
		for (int i=0;i<length;i++) {
			int arg=((Integer)it.next()).intValue();
			os.write(' ');
			C14n.writeAttribute(in,arg,os);
			os.write(EQ);
			os.write(in.getAttributeValue(arg).getBytes());
			os.write('\"');			
		}
			
		return;
	}	

	}



