/*
 * Created on 22/apr/07
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.apache.james.jspf;

import org.apache.james.jspf.core.IResponse;

import java.util.List;

public class ResponseImpl implements IResponse {
    private Exception exception = null;
    private List value = null;
    private Object id = null;
    public ResponseImpl(Object id, Exception e) {
        this.exception = e;
        this.id = id;
    }
    public ResponseImpl(Object id, List result) {
        this.value = result;
        this.id = id;
    }
    public Exception getException() {
        return exception;
    }
    public Object getId() {
        return id;
    }
    public Object getValue() {
        return value;
    }
}