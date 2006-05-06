/*
 * Created on 4-mag-2006
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.apache.james.jspf;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.net.UnknownHostException;

import junit.framework.TestCase;

public class DNSServiceXBillImplTest extends TestCase {

    protected void setUp() throws Exception {
        super.setUp();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /*
     * Test method for
     * 'org.apache.james.jspf.DNSServiceXBillImpl.getLocalDomainNames()'
     */
    public void testGetLocalDomainNames() throws UnknownHostException,
            TextParseException {
        System.out.println(InetAddress.getLocalHost());
        System.out.println(InetAddress.getAllByName(null)[0]);
        System.out.println(InetAddress.getLocalHost().getCanonicalHostName());
        System.out.println(InetAddress.getAllByName(null)[0]
                .getCanonicalHostName());
        System.out.println(new Lookup(Name.root, Type.ANY).run()[0]);

    }

}
