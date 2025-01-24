package org.apache.james.jspf;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.helpers.FakeResolver;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.SPF;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;

public abstract class SPFExecutorBaseTest {
    protected final String zonesDir = "src/test/resources/dnszones";

    protected abstract SPF createSPF();

    protected abstract SPF createCustomSPF(DNSService dnsService);

    @Before
    public void clearDnsCache() {
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }

    public String getZonePath(String zoneFile) {
        return Paths.get(zonesDir, zoneFile).toAbsolutePath().toString();
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

    @Test
    public void shouldReturnPassIfJustOneTxtSpf1Record() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnPassIfJustOneTxtSpf1Record." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(testDomain, getZonePath("SPFExecutorIntegrationTest-1.zone"));
        fakeResolver.addRecords(FakeResolver.genNRandomTXTRecords(hostname + ".", 300));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: domain of %2$s designates %1$s as permitted sender) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PASS_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test
    public void shouldReturnErrorIfMoreThanOneTxtSpf1Record() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnErrorIfMoreThanOneTxtSpf1Record." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(testDomain, getZonePath("SPFExecutorIntegrationTest-1.zone"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PERM_ERROR_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test
    public void shouldReturnErrorIfMoreThanOneSpfRecord() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnErrorIfMoreThanOneSpfRecord." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.setRecords(FakeResolver.genNRandomTXTRecords(hostname + ".", 300));
        fakeResolver.addRecord(new SPFRecord(
                Name.fromString(hostname + "."), DClass.IN, 30L, String.format("v=spf1 ip4:%s ip4:1.1.1.1 -all", ip)));
        fakeResolver.addRecord(new SPFRecord(
                Name.fromString(hostname + "."), DClass.IN, 30L, String.format("v=spf1 ip4:%s -all", ip)));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PERM_ERROR_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    /*
     * Test the limit described in RFC7208 section "4.6.4.  DNS Lookup Limits"
     */
    @Test
    public void shouldReturnErrorIfDepthMoreThan10() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnErrorIfDepthMoreThan10." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."),
                DClass.IN, 30L, String.format("v=spf1 ip4:4.3.2.1 include:depth0.%s -all", hostname)));

        fakeResolver.addRecords(IntStream.range(0, 10).mapToObj(
                i -> {
                    try {
                        String txt = String.format("v=spf1 ip4:4.3.2.2 include:depth%s.%s -all", i + 1, hostname);
                        return new TXTRecord(
                                Name.fromString(String.format("depth%s.%s.", i, hostname), Name.fromString(testDomain)),
                                DClass.IN, 30L, txt);
                    } catch (TextParseException e) {
                        throw new RuntimeException(e);
                    }
                }).collect(Collectors.toList()));


        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PERM_ERROR_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    /*
     * Test the limit described in RFC7208 section "4.6.4.  DNS Lookup Limits"
     */
    @Test
    public void shouldReturnPassIfDepth10orLess() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnPassIfDepth10OrLess." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."),
                DClass.IN, 30L, String.format("v=spf1 ip4:4.3.2.1 include:depth0.%s -all", hostname)));

        int count = 10;
        fakeResolver.addRecords(IntStream.range(0, count).mapToObj(
                i -> {
                    try {
                        String txt;
                        if (i == count - 1) {
                            txt = String.format("v=spf1 ip4:4.3.2.2 ip4:%s -all", ip);
                        } else {
                            txt = String.format("v=spf1 ip4:4.3.2.2 include:depth%s.%s -all", i + 1, hostname);
                        }
                        return new TXTRecord(
                                Name.fromString(String.format("depth%s.%s.", i, hostname), Name.fromString(testDomain)),
                                DClass.IN, 30L, txt);
                    } catch (TextParseException e) {
                        throw new RuntimeException(e);
                    }
                }).collect(Collectors.toList()));


        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: domain of %2$s designates %1$s as permitted sender) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PASS_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test
    public void shouldReturnPermErrorIfIncludeDomainNotFound() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnPermErrorIfIncludeDomainNotFound." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(testDomain, getZonePath("SPFExecutorIntegrationTest-1.zone"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PERM_ERROR_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test
    public void shouldHandleMultipleStrings() throws IOException {
        String testDomain = "spfexecutor.fake";
        String hostname = "shouldReturnPassIfMultipleStrings." + testDomain;
        String ip = "192.0.2.127";

        //setup resolver
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(testDomain, getZonePath("SPFExecutorIntegrationTest-1.zone"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: domain of %2$s designates %1$s as permitted sender) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PASS_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }
}
