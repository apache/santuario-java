/*
 * Copyright 2005 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
/*
 * $Id$
 */
package org.jcp.xml.dsig.internal.dom;

import javax.xml.crypto.NodeSetData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.NoSuchElementException;
import org.w3c.dom.DOMException;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.traversal.NodeFilter;
import org.w3c.dom.traversal.NodeIterator;

/**
 * This is a subtype of NodeSetData that represents a dereferenced
 * same-document URI as the root of a subdocument. The main reason is
 * for efficiency and performance, as some transforms can operate
 * directly on the subdocument and there is no need to convert it
 * first to an XPath node-set.
 */
public class SubDocumentData implements NodeSetData {

    public static final int SHOW_ALL_EXCEPT_COMMENTS =
        NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_PROCESSING_INSTRUCTION | 
        NodeFilter.SHOW_TEXT | NodeFilter.SHOW_CDATA_SECTION | 
        NodeFilter.SHOW_DOCUMENT | NodeFilter.SHOW_ATTRIBUTE |
        NodeFilter.SHOW_DOCUMENT_FRAGMENT | NodeFilter.SHOW_DOCUMENT_TYPE | 
	NodeFilter.SHOW_ENTITY | NodeFilter.SHOW_ENTITY_REFERENCE | 
        NodeFilter.SHOW_NOTATION;

    private boolean withComments;
    private NodeIterator ni;

    public SubDocumentData(Node root, boolean withComments, 
	NodeFilter twFilter) {
	this.ni = new DelayedNodeIterator(root, withComments);
	this.withComments = withComments;
    }

    public Iterator iterator() {
        return new Iterator() {
            public boolean hasNext() {
                if (ni.nextNode() == null) {
                    return false;
                } else {
                    ni.previousNode();
                    return true;
                }
            }

            public Object next() {
                Node node = ni.nextNode();
                if (node == null) {
                    throw new NoSuchElementException();
                } else {
                    return node;
                }
            }

            public void remove() {
                throw new UnsupportedOperationException();
            }
        };
    }

    public boolean withComments() {
	return withComments;
    }

    public NodeIterator nodeIterator() {
	return ni;
    }

    /**
     * This is a NodeIterator that contains a backing node-set that is
     * not populated until the caller first attempts to advance the iterator.
     */
    static class DelayedNodeIterator implements NodeIterator {
    	private Node root;
	private List nodeSet;
	private ListIterator li;
	private boolean detached = false;
	private boolean withComments;

	DelayedNodeIterator(Node root, boolean withComments) {
            this.root = root;
            this.withComments = withComments;
	}

	public int getWhatToShow() {
	    if (withComments) {
	        // show everything 
		return NodeFilter.SHOW_ALL;
	    } else {
	        // show everything but comment nodes
		return SHOW_ALL_EXCEPT_COMMENTS;
	    }
	}

	public Node getRoot() {
            return root;
	}

	public NodeFilter getFilter() {
            return null;
	}

	public Node nextNode() throws DOMException {
            if (detached) {
		throw new DOMException(DOMException.INVALID_STATE_ERR, "");
            }
            if (nodeSet == null) {
		nodeSet = dereferenceSameDocumentURI(root);
		li = nodeSet.listIterator();
            }
            if (li.hasNext()) {
		return (Node) li.next();
            } else {
		return null;
	    }
	}

	public Node previousNode() throws DOMException {
            if (detached) {
		throw new DOMException(DOMException.INVALID_STATE_ERR, "");
            }
            if (nodeSet == null) {
		nodeSet = dereferenceSameDocumentURI(root);
		li = nodeSet.listIterator();
            }
            if (li.hasPrevious()) {
		return (Node) li.previous();
            } else {
		return null;
            }
	}

	public boolean getExpandEntityReferences() {
            return true;
	}

	public void detach() {
            detached = true;
	}

	/**
         * Dereferences a same-document URI fragment.
	 *
	 * @param node the node (document or element) referenced by the
         *	 URI fragment. If null, returns an empty set.
	 * @return a set of nodes (minus any comment nodes)
	 */
	private List dereferenceSameDocumentURI(Node node) {
            List nodeSet = new ArrayList();
            if (node != null) {
		nodeSetMinusCommentNodes(node, nodeSet, null);
            }
            return nodeSet;
	}

	/**
         * Recursively traverses the subtree, and returns an XPath-equivalent
	 * node-set of all nodes traversed, excluding any comment nodes,
	 * if specified.
	 *
         * @param node the node to traverse
	 * @param nodeSet the set of nodes traversed so far
	 * @param the previous sibling node
	 */
	private void nodeSetMinusCommentNodes(Node node, List nodeSet,
            Node prevSibling) {
            switch (node.getNodeType()) {
		case Node.ELEMENT_NODE :
                    NamedNodeMap attrs = node.getAttributes();
                    if (attrs != null) {
                        for (int i = 0; i<attrs.getLength(); i++) {
                            nodeSet.add(attrs.item(i));
                        }
                    }
                    nodeSet.add(node);
                    Node pSibling = null;
                    for (Node child = node.getFirstChild(); child != null;
                        child = child.getNextSibling()) {
			nodeSetMinusCommentNodes(child, nodeSet, pSibling);
                        pSibling = child;
                    }
                    break;
		case Node.TEXT_NODE :
		case Node.CDATA_SECTION_NODE:
                    // emulate XPath which only returns the first node in
                    // contiguous text/cdata nodes
                    if (prevSibling != null &&
                        (prevSibling.getNodeType() == Node.TEXT_NODE ||
                         prevSibling.getNodeType() == Node.CDATA_SECTION_NODE)){			return;
                    }
		case Node.PROCESSING_INSTRUCTION_NODE :
                    nodeSet.add(node);
	            break;
		case Node.COMMENT_NODE:
		    if (withComments) { 
                        nodeSet.add(node);
		    }
            }
	}
    }
}
