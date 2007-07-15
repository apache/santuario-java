package com.r_bg.stax.c14n;

import java.io.IOException;
import java.io.OutputStream;

import javax.xml.stream.XMLStreamReader;

public interface C14nAttributeHandler {
	public void handleAttributes(XMLStreamReader in,StaxC14nHelper nsD, OutputStream os) throws IOException;
}
