package com.r_bg.stax.c14n;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.xml.namespace.QName;
import javax.xml.stream.EventFilter;
import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.events.XMLEvent;


public class C14n implements EventFilter,StreamFilter {
	//String result="";
	static final byte[] END_EL={'<','/'}; 
	static void writePiData(XMLStreamReader in,OutputStream os) throws IOException {
		os.write(in.getPITarget().getBytes());
		String data=in.getPIData();
		if (data!=null && data.length()!=0) {
			os.write(' ');
			os.write(data.getBytes());
		}
	}
	static void obtainName(QName name,OutputStream os) throws IOException {		
		String prefix=name.getPrefix();		
		if (prefix!=null && prefix.length()!=0) {
			os.write(prefix.getBytes());
			os.write(':');
		}
		os.write(name.getLocalPart().getBytes());
	}
	static void writeAttribute(XMLStreamReader in, int i, OutputStream os) throws IOException {
		String result=in.getAttributePrefix(i);
		if (result!=null && result.length()!=0) {
			os.write(result.getBytes());
			os.write(':');
		}
		os.write(in.getAttributeLocalName(i).getBytes());		
	}
	public static String cannoicalizeWithoutComments(XMLStreamReader in, C14nAttributeHandler handler) throws XMLStreamException, IOException {		
		ByteArrayOutputStream os=new ByteArrayOutputStream();
		int type;
		int beforeDocumentElement=1;
		StaxC14nHelper nsD=new StaxC14nHelper();
		int number=0;
		while ((type=in.getEventType())!=XMLStreamReader.END_DOCUMENT) {
			switch (type) {
			case XMLStreamReader.PROCESSING_INSTRUCTION:
				if (beforeDocumentElement==-1)
					os.write('\n');
				os.write("<?".getBytes());
				writePiData(in,os);
				os.write("?>".getBytes());
				if (beforeDocumentElement==1)
					os.write('\n');
				break;
			case XMLStreamReader.START_ELEMENT:
				number++;
				nsD.push();
				beforeDocumentElement=0;
				os.write('<');
				obtainName(in.getName(),os);
				handler.handleAttributes(in,nsD,os);
				os.write('>');
				break;
			case XMLStreamReader.END_ELEMENT:
				if (--number==0) {
					beforeDocumentElement=-1;
				}
				os.write(END_EL);
				obtainName(in.getName(),os);
				os.write('>');
				nsD.pop();
				break;

			case XMLStreamReader.CHARACTERS:
			case XMLStreamReader.CDATA:
				os.write(in.getText().getBytes());
				break;			
						}
			in.next();
		}
		return new String(os.toByteArray());
	}

	int beforeDocumentElement=-1;
	int number=0;
	C14nAttributeHandler handler;
	StaxC14nHelper nsD=new StaxC14nHelper();
	OutputStream os;
	public C14n(C14nAttributeHandler handler, OutputStream os) {
		this.handler=handler;
		this.os=os;
	}
	public boolean accept(XMLEvent arg0) {
		return false;
	}
	public boolean accept(XMLStreamReader in)  {
		try {
		int type=in.getEventType();
		switch (type) {
			case XMLStreamReader.PROCESSING_INSTRUCTION:
				if (beforeDocumentElement==-1)
					os.write('\n');
				os.write("<?".getBytes());
				writePiData(in,os);
				os.write("?>".getBytes());
				if (beforeDocumentElement==1)
					os.write('\n');
				break;
			case XMLStreamReader.START_ELEMENT:
				number++;
				nsD.push();
				beforeDocumentElement=0;
				os.write('<');
				obtainName(in.getName(),os);
				handler.handleAttributes(in,nsD,os);
				os.write('>');
				break;
			case XMLStreamReader.END_ELEMENT:
				if (--number==0) {
					beforeDocumentElement=-1;
				}
				os.write(END_EL);
				obtainName(in.getName(),os);
				os.write('>');
				nsD.pop();
				break;

			case XMLStreamReader.CHARACTERS:
			case XMLStreamReader.CDATA:
				os.write(in.getText().getBytes());
				break;
			
		}
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		return true;
	}
}
	



