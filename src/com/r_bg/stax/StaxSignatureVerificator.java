package com.r_bg.stax;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.stream.StreamFilter;
import javax.xml.stream.XMLStreamReader;


class IdWatcher implements StaxWatcher {
	String uri;
	DigestResultListener re;
	OutputStream os;
	public IdWatcher(String uri, DigestResultListener reader,OutputStream os) {
		this.uri=uri;
		this.re=reader;
		this.os=os;
	}
	public StaxWorker watch(XMLStreamReader reader, StaxSignatureVerificator sig) {
		if (uri.equals(reader.getAttributeValue(null, "Id"))) {
			return new C14nWorker(re,os);
		}
		return null;
	}
	
}

public class StaxSignatureVerificator implements StreamFilter{
	List<XMLSignatureWorker> signatures=new ArrayList<XMLSignatureWorker>();
	List<StaxWorker> filters=new ArrayList<StaxWorker>();
	List<Integer> filterStart=new ArrayList<Integer>();
	List<StaxWatcher> watchers=new ArrayList<StaxWatcher>();
	int level=0;
	public StaxSignatureVerificator() {
		watchers.add(new SignatureWatcher());
	}
	public void addSignature(XMLSignatureWorker s) {
		signatures.add(s);
		
	}
	public void insertWatch(IdWatcher watcher) {
		watchers.add(watcher);
		
	}
	public boolean accept(XMLStreamReader cur) {
		int eventType = cur.getEventType();
		if (eventType==XMLStreamReader.START_ELEMENT) {
			//Start element notify all watcher
			level++;
			for (StaxWatcher watcher : watchers) {
				StaxWorker sf=watcher.watch(cur, this);
				if (sf!=null) {
					//Add a new worker
					filters.add(sf);
					filterStart.add(level);
				}
			}
		}
		List<StaxWorker> added=filters;
		//A worker can add new workers. Iterate while there is more workers to add.
		while (added.size()!=0) {			
			List<StaxWorker> toAdd=new ArrayList<StaxWorker>();
			List<Integer> toAddStart=new ArrayList<Integer>();						
			for (StaxWorker filter: added) {
				StaxWorker sf=filter.read(cur);
				if (sf!=null) {
					toAdd.add(sf);
					toAddStart.add(level);
				}
			}			
			added=toAdd;
			filters.addAll(toAdd);
			filterStart.addAll(toAddStart);
		}
		if (eventType==XMLStreamReader.END_ELEMENT) {
			//an end element remove any worker attached to this element
			do {
				int i=filterStart.lastIndexOf(level);
				if (i!=-1) {
					StaxWatcher watch=filters.remove(i).remove();
					if (watch!=null) {
						watchers.add(watch);
					}
					filterStart.remove(i);
				}
			} while (filterStart.contains(level));
			level--;
		}
		return true;
	}
}
