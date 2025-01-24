package org.apache.james.jspf;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.SPF;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.assertEquals;

public abstract class SPFExecutorBaseTest {

    protected abstract SPF createSPF();

    protected abstract SPF createCustomSPF(DNSService dnsService);

    @Before
    public void clearDnsCache() {
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }

    @Test
    public void test() {
        SPF spf = createSPF();
        SPFResult result = spf.checkSPF("109.197.176.25", "nico@linagora.com", "linagora.com");
        assertEquals("pass", result.getResult());
        assertEquals("Received-SPF: pass (spfCheck: domain of linagora.com designates 109.197.176.25 as permitted sender) client-ip=109.197.176.25; envelope-from=nico@linagora.com; helo=linagora.com;",
                result.getHeader());
    }

    @Test
    public void shouldHandleDomainNotFound() {
        SPF spf = createSPF();
        SPFResult result = spf.checkSPF("207.54.72.202",
                "do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de",
                "reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de");
        assertEquals("none", result.getResult());
        assertEquals("Received-SPF: none (spfCheck: 207.54.72.202 is neither permitted nor denied by domain of reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de) client-ip=207.54.72.202; envelope-from=do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de; helo=reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de;",
                result.getHeader());
    }

    @Test
    public void shouldHandleSPFNotFound() {
        SPF spf = createSPF();
        SPFResult result = spf.checkSPF("207.54.72.202", "do_not_reply@com.br", "com.br");
        assertEquals("none", result.getResult());
        assertEquals("Received-SPF: none (spfCheck: 207.54.72.202 is neither permitted nor denied by domain of com.br) client-ip=207.54.72.202; envelope-from=do_not_reply@com.br; helo=com.br;",
                result.getHeader());
    }

    @Test
    public void shouldReturnTempErrorOnPortUnreachable() throws UnknownHostException {
        Resolver simpleResolver = new SimpleResolver("127.0.0.1");
        simpleResolver.setPort(ThreadLocalRandom.current().nextInt(55000, 56000));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(simpleResolver));
        SPFResult result = spf.checkSPF("207.54.72.202",
                "do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de",
                "reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de");
        assertEquals("temperror", result.getResult());
        assertEquals("Received-SPF: temperror (spfCheck: Error in retrieving data from DNS) client-ip=207.54.72.202; envelope-from=do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de; helo=reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de;",
                result.getHeader());
    }
}
