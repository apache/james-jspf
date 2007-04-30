/****************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one   *
 * or more contributor license agreements.  See the NOTICE file *
 * distributed with this work for additional information        *
 * regarding copyright ownership.  The ASF licenses this file   *
 * to you under the Apache License, Version 2.0 (the            *
 * "License"); you may not use this file except in compliance   *
 * with the License.  You may obtain a copy of the License at   *
 *                                                              *
 *   http://www.apache.org/licenses/LICENSE-2.0                 *
 *                                                              *
 * Unless required by applicable law or agreed to in writing,   *
 * software distributed under the License is distributed on an  *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
 * KIND, either express or implied.  See the License for the    *
 * specific language governing permissions and limitations      *
 * under the License.                                           *
 ****************************************************************/

package org.apache.james.jspf.impl;

import org.apache.james.jspf.core.DNSAsynchLookupService;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IResponse;
import org.apache.james.jspf.core.IResponseQueue;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.NonblockingResolver;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import uk.nominet.dnsjnio.Response;
import uk.nominet.dnsjnio.ResponseQueue;

import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class DNSJnioAsynchService implements DNSAsynchLookupService {

    private final class ResponseQueueAdaptor extends ResponseQueue {

        private IResponseQueue responsePool;

        public ResponseQueueAdaptor(IResponseQueue responsePool) {
            this.responsePool = responsePool;
        }

        public void insert(final Response arg0) {
            IResponse resp = new IResponse() {

                public Exception getException() {
                    if (arg0.getException() != null) {
                        return new DNSService.TimeoutException();
                    } else {
                        return null;
                    }
                }

                public Object getId() {
                    return arg0.getId();
                }

                public Object getValue() {
                    Message response = arg0.getMessage();
                    RRset[] rrs = response.getSectionRRsets(Section.ANSWER);
                    List records = new LinkedList();
                    for (int i = 0; i < rrs.length; i++) {
                        for (Iterator it = rrs[i].rrs(); it.hasNext(); ) {
                            records.add(it.next());
                        }
                    }
                    return DNSServiceXBillImpl.convertRecordsToList((Record[]) records.toArray(new Record[]{}));
                    
                }
                
            };
            responsePool.insertResponse(resp);
        }

        public boolean isEmpty() {
            return responsePool.isEmpty();
        }
        
        public Response getItem() {
            IResponse found = responsePool.removeResponse();
            Response resp = new Response();
            if (found.getException() != null) {
                resp.setException(true);
                resp.setException(found.getException());
            } else {
                resp.setException(false);
                resp.setMessage((Message) found.getValue());
            }
            resp.setId(found.getId());
            return resp;
        }
        
        
    }

    private NonblockingResolver resolver;

    public DNSJnioAsynchService() {
        try {
            this.resolver = new NonblockingResolver("127.0.0.1");
            this.resolver.setPort(35347);
            this.resolver.setTCP(false);
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    public void setTimeout(int timeout) {
        this.resolver.setTimeout(timeout);
    }
    
    /**
     * @see org.apache.james.jspf.core.DNSAsynchLookupService#getRecordsAsynch(org.apache.james.jspf.core.DNSRequest, java.lang.Object, org.apache.james.jspf.core.IResponseQueue)
     */
    public void getRecordsAsynch(DNSRequest request, int id,
            IResponseQueue responsePool) {
        
        Message message;
        try {
            message = makeQuery(request, id);
            this.resolver.sendAsync(message, new Integer(id), new ResponseQueueAdaptor(responsePool));
        } catch (TextParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private Message makeQuery(DNSRequest request, int id) throws TextParseException {
        Name name = Name.fromString(request.getHostname(), Name.root);
        
        int type;
        switch (request.getRecordType()) {
            case DNSRequest.A: type = Type.A; break;
            case DNSRequest.AAAA: type = Type.AAAA; break;
            case DNSRequest.MX: type = Type.MX; break;
            case DNSRequest.PTR: type = Type.PTR; break;
            case DNSRequest.SPF: type = Type.SPF; break;
            case DNSRequest.TXT: type = Type.TXT; break;
            default: 
                throw new UnsupportedOperationException("Unknown query type: "+request.getRecordType());
        }
        
        Record question = Record.newRecord(name, type, DClass.ANY);
        Message query = Message.newQuery(question);
        query.getHeader().setID(id);
        return query;
    }
}
