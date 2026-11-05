package org.apache.james.jspf;

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.helpers.AnsweringResolver;
import org.apache.james.jspf.helpers.FakeResolver;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.SPF;
import org.apache.james.jspf.policies.local.TrustedForwarderPolicy;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.NoSuchRRSetException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;

public abstract class SPFExecutorBaseTest {
    protected final String zonesDir = "src/test/resources/dnszones";

    // one TXT record made of 255 byte strings, as DNS carries a long record
    private static TXTRecord longTxtRecord(String hostname, String record) throws TextParseException {
        List<String> strings = IntStream.range(0, (record.length() + 254) / 255)
            .mapToObj(i -> record.substring(i * 255, Math.min(record.length(), (i + 1) * 255)))
            .collect(Collectors.toList());
        return new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, strings);
    }

    // hostname includes target.<hostname>, whose record fails, then ends with lastTerm
    private static FakeResolver includeOfAFailingRecord(String hostname, String lastTerm) throws IOException {
        String target = "target." + hostname;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            "v=spf1 include:" + target + " " + lastTerm));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(target + "."), DClass.IN, 30L, "v=spf1 -all"));
        return fakeResolver;
    }

    // hostname has "v=spf1 <ptrTerm> -all", and 1.2.3.4 the validated name <ptrName>
    private static FakeResolver ptrOfTheClient(String hostname, String ptrTerm, String ptrName) throws IOException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            "v=spf1 " + ptrTerm + " -all"));
        fakeResolver.addRecord(new PTRRecord(Name.fromString("4.3.2.1.in-addr.arpa."), DClass.IN, 30L,
            Name.fromString(ptrName)));
        fakeResolver.addRecord(new ARecord(Name.fromString(ptrName), DClass.IN, 30L,
            InetAddress.getByName("1.2.3.4")));
        return fakeResolver;
    }

    // a server publishing the record, failing the lookups of the given DNSRequest type
    private static DNSService dnsFailing(int failedType, Record record) throws IOException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(record);
        return new DNSServiceXBillImpl(fakeResolver) {
            @Override
            public List<String> getRecords(DNSRequest request) throws TimeoutException {
                if (request.getRecordType() == failedType) {
                    throw new TimeoutException("SERVFAIL");
                }
                return super.getRecords(request);
            }

            @Override
            public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
                if (request.getRecordType() == failedType) {
                    return CompletableFuture.failedFuture(new TimeoutException("SERVFAIL"));
                }
                return super.getRecordsAsync(request);
            }
        };
    }

    // hostname publishes "v=spf1 -all" as TXT, on a server failing the lookups of the obsolete SPF type
    private static DNSService dnsFailingTheSpfType(String hostname) throws IOException {
        return dnsFailing(DNSRequest.SPF, new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
    }

    protected abstract SPF createSPF();

    protected abstract SPF createCustomSPF(DNSService dnsService);

    @Before
    public void clearDnsCache() {
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }

    public String getZonePath(String zoneFile) {
        return Paths.get(zonesDir, zoneFile).toAbsolutePath().toString();
    }

    private SPFResult checkRecord(String hostname, String record, String ipAddress) throws IOException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, record));
        return createCustomSPF(new DNSServiceXBillImpl(fakeResolver)).checkSPF(ipAddress, "a_user@" + hostname, hostname);
    }

    // record refers (%s) to target.<hostname>, of record targetRecord
    private SPFResult checkRecordWithTarget(String hostname, String record, String targetRecord) throws IOException {
        String target = "target." + hostname;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, String.format(record, target)));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(target + "."), DClass.IN, 30L, targetRecord));
        return createCustomSPF(new DNSServiceXBillImpl(fakeResolver)).checkSPF("192.0.2.10", "a_user@" + hostname, hostname);
    }

    // the lookups of broken.<hostname> fail with an unchecked exception, as dnsjava may do on an answer it cannot handle
    private SPFResult checkRecordWithBrokenHost(String hostname, String record) throws IOException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, record));
        String brokenHost = "broken." + hostname;
        DNSService dns = new DNSServiceXBillImpl(fakeResolver) {
            @Override
            public List<String> getRecords(DNSRequest request) throws TimeoutException {
                if (request.getHostname().equals(brokenHost)) {
                    throw new IllegalStateException("answer dnsjava cannot handle");
                }
                return super.getRecords(request);
            }

            @Override
            public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
                if (request.getHostname().equals(brokenHost)) {
                    return CompletableFuture.failedFuture(new IllegalStateException("answer dnsjava cannot handle"));
                }
                return super.getRecordsAsync(request);
            }
        };
        return createCustomSPF(dns).checkSPF("192.0.2.10", "a_user@" + hostname, hostname);
    }

    // the lookups of broken.<hostname> throw, instead of failing, an unchecked exception
    private SPFResult checkRecordWithThrowingHost(String hostname, String record) throws IOException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, record));
        String brokenHost = "broken." + hostname;
        DNSService dns = new DNSServiceXBillImpl(fakeResolver) {
            @Override
            public List<String> getRecords(DNSRequest request) throws TimeoutException {
                if (request.getHostname().equals(brokenHost)) {
                    throw new IllegalStateException("lookup service failure");
                }
                return super.getRecords(request);
            }

            @Override
            public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
                if (request.getHostname().equals(brokenHost)) {
                    throw new IllegalStateException("lookup service failure");
                }
                return super.getRecordsAsync(request);
            }
        };
        return createCustomSPF(dns).checkSPF("192.0.2.10", "a_user@" + hostname, hostname);
    }

    @Test
    public void test() {
        SPF spf = createSPF();
        SPFResult result = spf.checkSPF("109.197.176.25", "nico@linagora.com", "linagora.com");
        assertEquals("pass", result.getResult());
        assertEquals("Received-SPF: pass (spfCheck: domain of linagora.com designates 109.197.176.25 as permitted sender) client-ip=109.197.176.25; envelope-from=\"nico@linagora.com\"; helo=linagora.com;",
                result.getHeader());
    }

    @Test
    public void shouldHandleDomainNotFound() {
        SPF spf = createSPF();
        SPFResult result = spf.checkSPF("207.54.72.202",
                "do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de",
                "reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de");
        assertEquals("none", result.getResult());
        assertEquals("Received-SPF: none (spfCheck: 207.54.72.202 is neither permitted nor denied by domain of reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de) client-ip=207.54.72.202; envelope-from=\"do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de\"; helo=reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de;",
                result.getHeader());
    }

    @Test
    public void shouldHandleSPFNotFound() {
        SPF spf = createSPF();
        SPFResult result = spf.checkSPF("207.54.72.202", "do_not_reply@com.br", "com.br");
        assertEquals("none", result.getResult());
        assertEquals("Received-SPF: none (spfCheck: 207.54.72.202 is neither permitted nor denied by domain of com.br) client-ip=207.54.72.202; envelope-from=\"do_not_reply@com.br\"; helo=com.br;",
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
        assertEquals("Received-SPF: temperror (spfCheck: Error in retrieving data from DNS) client-ip=207.54.72.202; envelope-from=\"do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de\"; helo=reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de;",
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
                        "Received-SPF: %3$s (spfCheck: domain of %2$s designates %1$s as permitted sender) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
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
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
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
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
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
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
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
                        "Received-SPF: %3$s (spfCheck: domain of %2$s designates %1$s as permitted sender) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
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
                        "Received-SPF: %3$s (spfCheck: Error in processing SPF Record) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
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
                        "Received-SPF: %3$s (spfCheck: domain of %2$s designates %1$s as permitted sender) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.PASS_CONV),
                result.getHeader());
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test
    public void headerCommentShouldNotBeClosedByTheRedirectDomain() throws IOException {
        String hostname = "headerCommentShouldNotBeClosedByTheRedirectDomain.spfexecutor.fake";
        String target = "x)client-ip=203.0.113.9;(." + hostname;
        String ip = "192.0.2.127";

        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 redirect=" + target));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(target + "."), DClass.IN, 30L, "v=spf1 -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF(ip, "a_user@" + hostname, hostname);
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
        assertEquals(String.format(
                        "Received-SPF: %3$s (spfCheck: domain of x\\)client-ip=203.0.113.9;\\(.%2$s does not designate %1$s as permitted sender) client-ip=%1$s; envelope-from=\"a_user@%2$s\"; helo=%2$s;",
                        ip, hostname, SPFErrorConstants.FAIL_CONV),
                result.getHeader());
    }

    /**
     * Test the limit described in RFC7208 section "4.6.4.  DNS Lookup Limits"
     */
    @Test
    public void shouldLookUpNoMoreThan10MxNames() {
        AtomicInteger addressLookups = new AtomicInteger();
        DNSService dns = new DNSService() {
            public List<String> getRecords(DNSRequest request) {
                switch (request.getRecordType()) {
                    case DNSRequest.TXT:
                        return request.getHostname().equals("example.com")
                            ? new ArrayList<>(List.of("v=spf1 mx -all")) : null;
                    case DNSRequest.MX:
                        return IntStream.range(0, 400).mapToObj(i -> "m" + i + ".example.net")
                            .collect(Collectors.toCollection(ArrayList::new));
                    case DNSRequest.A:
                        addressLookups.incrementAndGet();
                        return null;
                    default:
                        return null;
                }
            }

            public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
                return CompletableFuture.completedFuture(getRecords(request));
            }

            public List<String> getLocalDomainNames() {
                return List.of("localhost");
            }

            public void setTimeOut(int timeOut) {
            }

            public int getRecordLimit() {
                return 10;
            }

            public void setRecordLimit(int recordLimit) {
            }
        };

        SPFResult result = createCustomSPF(dns).checkSPF("1.2.3.4", "foo@example.com", "example.com");

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
        assertEquals(10, addressLookups.get());
    }

    @Test(timeout = 10000)
    public void shouldReturnFailWhenExplanationDomainHasNoTxtRecord() throws IOException {
        String hostname = "shouldReturnFailWhenExplanationDomainHasNoTxtRecord.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L,
                "v=spf1 -all exp=explain." + hostname));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("192.0.2.127", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldHandleRecordWithManyTerms() throws IOException {
        String hostname = "shouldHandleRecordWithManyTerms.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(longTxtRecord(hostname,
            "v=spf1 " + String.join(" ", Collections.nCopies(3000, "ip4:192.0.2.1")) + " -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldHandleRecordWithLongDomainSpec() throws IOException {
        String hostname = "shouldHandleRecordWithLongDomainSpec.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        // the include target, truncated to 253 characters from the left, is a subdomain of hostname,
        // with no record: FakeResolver answers it without querying the real DNS
        fakeResolver.addRecord(longTxtRecord(hostname, "v=spf1 include:" + "%{d}.".repeat(5000) + hostname + " -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void trustedForwarderShouldNotBeAddedToARedirectAfterANestedInclude() throws IOException {
        String hostname = "trustedForwarderRedirectAfterInclude.spfexecutor.fake";
        String child = "child." + TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST;
        String destination = "destination." + TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST + "."), DClass.IN, 30L,
            "v=spf1 include:" + child + " redirect=" + destination));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(child + "."), DClass.IN, 30L, "v=spf1 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(destination + "."), DClass.IN, 30L, "v=spf1 ip4:192.0.2.202 -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.setUseTrustedForwarder(true);

        assertEquals(SPFErrorConstants.FAIL_CONV, spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname).getResult());
        assertEquals(SPFErrorConstants.PASS_CONV, spf.checkSPF("192.0.2.202", "a_user@" + hostname, hostname).getResult());
    }

    @Test(timeout = 10000)
    public void trustedForwarderShouldKeepTheResultOfTheRecord() throws IOException {
        String hostname = "trustedForwarderShouldKeepTheResultOfTheRecord.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST + "."), DClass.IN, 30L,
            "v=spf1 ip4:192.0.2.200 -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.setUseTrustedForwarder(true);
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void trustedForwarderShouldPassTheForwarderListedByTheTrustedForwarderHost() throws IOException {
        String hostname = "trustedForwarderShouldPassListedForwarder.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST + "."), DClass.IN, 30L,
            "v=spf1 ip4:192.0.2.200 -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.setUseTrustedForwarder(true);
        SPFResult result = spf.checkSPF("192.0.2.200", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void trustedForwarderShouldNotBeAddedToTheRecordsItIncludes() throws IOException {
        String hostname = "trustedForwarderNotAddedToIncluded.spfexecutor.fake";
        String child = "child." + TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(TrustedForwarderPolicy.TRUSTED_FORWARDER_HOST + "."), DClass.IN, 30L,
            "v=spf1 include:" + child + " ip4:192.0.2.201 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(child + "."), DClass.IN, 30L, "v=spf1 -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.setUseTrustedForwarder(true);
        SPFResult result = spf.checkSPF("192.0.2.201", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnPermErrorOnIp4CidrOverflowingAnInt() throws IOException {
        SPFResult result = checkRecord("ip4CidrOverflow.spfexecutor.fake", "v=spf1 ip4:192.0.2.1/4294967296 -all", "1.2.3.4");

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnPermErrorOnIp6CidrOverflowingAnInt() throws IOException {
        SPFResult result = checkRecord("ip6CidrOverflow.spfexecutor.fake", "v=spf1 ip6:2001:db8::/99999999999 -all", "1.2.3.4");

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnPermErrorWhenIncludeHostIsNotADomainName() throws IOException {
        String hostname = "includeHostNotADomainName.spfexecutor.fake";
        SPFResult result = checkRecord(hostname, "v=spf1 include:a.." + hostname + " -all", "192.0.2.127");

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ipv4MappedIp6NetworkShouldNotMatchAnIp4Client() throws IOException {
        SPFResult result = checkRecord("ipv4MappedIp6Network.spfexecutor.fake", "v=spf1 ip6:::ffff:0.2.3.4/3 -all", "1.2.3.4");

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ipv4MappedIp6NetworkShouldKeepItsIp6PrefixLength() throws IOException {
        // ::ffff:0.2.3.4/3 is ::/3
        SPFResult result = checkRecord("ipv4MappedIp6Prefix.spfexecutor.fake", "v=spf1 ip6:::ffff:0.2.3.4/3 -all", "::1");

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void aShouldMatchAnIpv4MappedClientWithAZeroOctet() throws IOException {
        String hostname = "ipv4MappedClient.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 a -all"));
        fakeResolver.addRecord(new ARecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            InetAddress.getByName("10.0.0.1")));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("::ffff:10.0.0.1", "a_user@" + hostname, hostname);

        // RFC 7208 5: an IPv4-mapped address is an IPv4 address
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void inAddressShouldBeThatOfAnIpv4MappedClient() throws IOException {
        String hostname = "ipv4MappedInAddress.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            "v=spf1 exists:%{v}." + hostname + " -all"));
        fakeResolver.addRecord(new ARecord(Name.fromString("in-addr." + hostname + "."), DClass.IN, 30L,
            InetAddress.getByName("127.0.0.2")));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("::ffff:1.2.3.4", "a_user@" + hostname, hostname);

        // RFC 7208 7.3: %{v} is "in-addr" for an IPv4 client, which an IPv4-mapped one is (RFC 7208 5)
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void overrideEntryShouldReplaceTheRecordOfTheDomainItNames() throws IOException {
        String hostname = "override.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.getOverridePolicy().addEntry(hostname, "v=spf1 +all");

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void fallbackEntryShouldGiveARecordToTheDomainsUnderItsDomain() throws IOException {
        String hostname = "fallback.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        // no SPF record: an address only, so that FakeResolver answers the name
        fakeResolver.addRecord(new ARecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            InetAddress.getByName("192.0.2.1")));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.getFallbackPolicy().addEntry("*.spfexecutor.fake", "v=spf1 +all");

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void overrideWildcardEntryShouldNotApplyToALabelHoldingADot() throws IOException {
        String domain = "wildcard.spfexecutor.fake";
        // the labels "mail.wildcard", "spfexecutor" and "fake": not under domain
        String hostname = "mail\\." + domain;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        spf.getOverridePolicy().addEntry("*." + domain, "v=spf1 +all");

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // not the pass of the override: the sender domain, holding a backslash, is malformed (RFC 7208 4.3)
        assertEquals(SPFErrorConstants.NONE_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ptrShouldMatchADomainInUpperCase() throws IOException {
        String hostname = "ptrcase.spfexecutor.fake";
        FakeResolver fakeResolver = ptrOfTheClient(hostname, "ptr:" + hostname.toUpperCase(Locale.ROOT),
            "mail." + hostname + ".");
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ptrShouldMatchASenderDomainWithATrailingDot() throws IOException {
        String hostname = "ptrdot.spfexecutor.fake";
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(ptrOfTheClient(hostname, "ptr", "mail." + hostname + ".")));

        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname + ".", hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ptrShouldNotMatchALabelHoldingADotAsASubdomain() throws IOException {
        String hostname = "ptrlabel.spfexecutor.fake";
        // the labels "mail.ptrlabel", "spfexecutor" and "fake": a sibling of hostname, not a subdomain
        FakeResolver fakeResolver = ptrOfTheClient(hostname, "ptr", "mail\\." + hostname + ".");
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheLookupGetsAServerFailure() {
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(AnsweringResolver.withRcode(Rcode.SERVFAIL)));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@servfail.spfexecutor.fake", "servfail.spfexecutor.fake");

        // RFC 7208 4.4: "a server failure (RCODE 2) or some other error (RCODE other than 0 or 3)"
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheLookupGetsAnotherErrorRcode() {
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(AnsweringResolver.withRcode(Rcode.NXRRSET)));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@nxrrset.spfexecutor.fake", "nxrrset.spfexecutor.fake");

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheLookupGetsAnExtendedErrorRcode() {
        // BADVERS (16): 0 in the header, the upper bits in the OPT record (RFC 6891 6.1.3)
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(AnsweringResolver.withRcode(Rcode.BADVERS)));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@badvers.spfexecutor.fake", "badvers.spfexecutor.fake");

        // RFC 7208 4.4: "some other error (RCODE other than 0 or 3)"
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheLookupGetsANetworkError() {
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(AnsweringResolver.unreachable()));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@unreachable.spfexecutor.fake", "unreachable.spfexecutor.fake");

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldFollowTheFirstOfSeveralCnamesOfTheDomain() throws IOException {
        String hostname = "cnames.spfexecutor.fake";
        // three CNAME records of the domain, where RFC 2181 10.1 allows one, each to its own record
        Message answer = new Message();
        answer.getHeader().setFlag(Flags.QR);
        String[] records = {"v=spf1 -all", "v=spf1 +all", "v=spf1 ?all"};
        for (int i = 0; i < records.length; i++) {
            Name target = Name.fromString("target" + i + "." + hostname + ".");
            answer.addRecord(new CNAMERecord(Name.fromString(hostname + "."), DClass.IN, 30L, target), Section.ANSWER);
            answer.addRecord(new TXTRecord(target, DClass.IN, 30L, records[i]), Section.ANSWER);
        }
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(new AnsweringResolver(answer.toWire())));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // the record of the first CNAME, whatever the executor
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnNoneWhenTheLookupGetsACnameOfAnotherClass() throws IOException {
        String hostname = "cnameOfAnotherClass.spfexecutor.fake";
        // NOERROR, and a CNAME of the name queried in class CH: no record of class IN
        Message answer = new Message();
        answer.getHeader().setFlag(Flags.QR);
        answer.addRecord(new CNAMERecord(Name.fromString(hostname + "."), DClass.CH, 30L,
            Name.fromString("other." + hostname + ".")), Section.ANSWER);
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(new AnsweringResolver(answer.toWire())));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // as for a domain without SPF record (RFC 7208 4.5)
        assertEquals(SPFErrorConstants.NONE_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void aShouldLookUpATargetThatReadsAsAnAddress() throws IOException {
        String hostname = "aTargetAddress.spfexecutor.fake";
        // the names of no record of fakeResolver do not exist
        FakeResolver fakeResolver = new FakeResolver(AnsweringResolver.withRcode(Rcode.NXDOMAIN));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 a:%{i} -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        // RFC 7208 5.3: the target 1.2.3.4 is a domain name, of no A record
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void aShouldLookUpATargetThatReadsAsAnIp6Address() throws IOException {
        String hostname = "aTargetIp6Address.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver(AnsweringResolver.withRcode(Rcode.NXDOMAIN));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 a:%{h} -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("2001:db8::1", "a_user@" + hostname, "2001:db8::1");

        // RFC 7208 5.3: the target is the HELO name, not the address it reads as
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnNoneForASenderDomainWithACharacterNoHostNameHolds() throws IOException {
        String hostname = "escaped.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        // read as a DNS name, escape\d is escaped
        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@escape\\d.spfexecutor.fake", "mail.spfexecutor.fake");

        // RFC 7208 4.3: a malformed domain gives none
        assertEquals(SPFErrorConstants.NONE_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void anOverrideShouldNotApplyToAMalformedSenderDomain() throws IOException {
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(new FakeResolver(AnsweringResolver.withRcode(Rcode.NXDOMAIN))));
        spf.getOverridePolicy().addEntry("escaped.spfexecutor.fake", "v=spf1 +all");

        // read as a DNS name, escape\d is escaped: the domain of the override entry
        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@escape\\d.spfexecutor.fake", "mail.spfexecutor.fake");

        // RFC 7208 4.3: a malformed domain gives none
        assertEquals(SPFErrorConstants.NONE_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldCheckASenderDomainWithAnUnderscore() throws IOException {
        String hostname = "_underscore.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ptrShouldNotMatchWhenThePtrLookupFails() throws IOException {
        String hostname = "ptrservfail.spfexecutor.fake";
        // the names of no record of fakeResolver, as the reverse name of the client, answer SERVFAIL
        FakeResolver fakeResolver = new FakeResolver(AnsweringResolver.withRcode(Rcode.SERVFAIL));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            "v=spf1 ptr ip4:192.0.2.10 -all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // RFC 7208 5.5: "If a DNS error occurs while doing the PTR RR lookup, then this mechanism fails to match"
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void ptrShouldSkipANameWhoseAddressLookupFails() throws IOException {
        String hostname = "ptrskip.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver(AnsweringResolver.withRcode(Rcode.SERVFAIL));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 ptr -all"));
        // the client is named by broken.servfail.fake, of no record here, then by mail.<hostname>
        fakeResolver.addRecord(new PTRRecord(Name.fromString("10.2.0.192.in-addr.arpa."), DClass.IN, 30L,
            Name.fromString("broken.servfail.fake.")));
        fakeResolver.addRecord(new PTRRecord(Name.fromString("10.2.0.192.in-addr.arpa."), DClass.IN, 30L,
            Name.fromString("mail." + hostname + ".")));
        fakeResolver.addRecord(new ARecord(Name.fromString("mail." + hostname + "."), DClass.IN, 30L,
            InetAddress.getByName("192.0.2.10")));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // RFC 7208 5.5: "If a DNS error occurs while doing an A RR lookup, then that domain name is skipped"
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldPreferTheTxtRecordToARecordOfTheSpfType() throws IOException {
        String hostname = "txtAndSpfType.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));
        // a stale record of the obsolete SPF type
        fakeResolver.addRecord(new SPFRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // RFC 7208 4.4: the record is looked up as "type TXT only"
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReadTheSpfTypeWhenNoTxtRecordIsAnSpfRecord() throws IOException {
        String hostname = "spfTypeOnly.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "site-verification=abc"));
        fakeResolver.addRecord(new SPFRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // as before RFC 7208, for a domain publishing its record as the obsolete SPF type only
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheTxtLookupFailsAlthoughTheSpfTypeHasARecord() throws IOException {
        String hostname = "txtservfail.spfexecutor.fake";
        DNSService dns = dnsFailing(DNSRequest.TXT,
            new SPFRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));

        SPFResult result = createCustomSPF(dns).checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // RFC 7208 4.4: the record is looked up as "type TXT only", a DNS error of which is a temperror
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldDiscardARecordThatDoesNotBeginWithTheVersion() throws IOException {
        String hostname = "leadingSpace.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, " v=spf1 +all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // RFC 7208 4.5: "discard records that do not begin with a version section of exactly "v=spf1""
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReadTheSpfTypeWhenNoTxtRecordBeginsWithTheVersion() throws IOException {
        String hostname = "leadingSpaceOnly.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, " v=spf1 +all"));
        fakeResolver.addRecord(new SPFRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 -all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldCheckTheTxtRecordWhenTheLookupOfTheSpfTypeFails() throws IOException {
        String hostname = "spftypeservfail.spfexecutor.fake";

        SPFResult result = createCustomSPF(dnsFailingTheSpfType(hostname)).checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        // RFC 7208 4.4: the record is looked up as "type TXT only"
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldCheckTheTxtRecordWhenTheLookupOfTheSpfTypeFailsInStrictMode() throws IOException {
        String hostname = "spftypeservfailstrict.spfexecutor.fake";
        SPF spf = createCustomSPF(dnsFailingTheSpfType(hostname));
        spf.setSPFMustEqualsTXT(true);

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void headerShouldNotHoldTheControlCharactersOfTheHelo() throws IOException {
        String hostname = "heloControl.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname + "\u0000");

        // RFC 7208 9.1: a value is a dot-atom or a quoted-string, of no control character (RFC 5322 3.2.4)
        assertEquals("Received-SPF: pass (spfCheck: domain of " + hostname + " designates 192.0.2.10 as permitted sender)"
            + " client-ip=192.0.2.10; envelope-from=\"a_user@" + hostname + "\"; helo=\"" + hostname + "\";", result.getHeader());
    }

    @Test(timeout = 10000)
    public void headerShouldKeepTheNonAsciiCharactersOfAMailFrom() throws IOException {
        String hostname = "mailFromUtf8.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        // a UTF-8 local part, of SMTPUTF8
        SPFResult result = spf.checkSPF("192.0.2.10", "pel\u00e9@" + hostname, hostname);

        // RFC 6532 3.2: UTF-8 in a header value
        assertEquals("Received-SPF: pass (spfCheck: domain of " + hostname + " designates 192.0.2.10 as permitted sender)"
            + " client-ip=192.0.2.10; envelope-from=\"pel\u00e9@" + hostname + "\"; helo=" + hostname + ";", result.getHeader());
    }

    @Test(timeout = 10000)
    public void headerShouldQuoteAMailFromThatWouldEndItsValue() throws IOException {
        String hostname = "mailFromQuote.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "\"a b;\"@" + hostname, hostname);

        assertEquals("Received-SPF: pass (spfCheck: domain of " + hostname + " designates 192.0.2.10 as permitted sender)"
            + " client-ip=192.0.2.10; envelope-from=\"\\\"a b;\\\"@" + hostname + "\"; helo=" + hostname + ";",
            result.getHeader());
    }

    @Test(timeout = 10000)
    public void headerShouldQuoteTheAddressOfAnIpv6Client() throws IOException {
        String hostname = "clientIpv6.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("2001:db8::10", "a_user@" + hostname, hostname);

        // RFC 7208 9.1: ":" is no atext (RFC 5322 3.2.3), so the address is no dot-atom
        assertEquals("Received-SPF: pass (spfCheck: domain of " + hostname + " designates 2001:db8::10 as permitted sender)"
            + " client-ip=\"2001:db8::10\"; envelope-from=\"a_user@" + hostname + "\"; helo=" + hostname + ";",
            result.getHeader());
    }

    @Test(timeout = 10000)
    public void headerShouldQuoteAHeloEndingWithADot() throws IOException {
        String hostname = "heloDot.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L, "v=spf1 +all"));
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname + ".");

        // RFC 7208 9.1: a dot-atom ends with atext (RFC 5322 3.2.3)
        assertEquals("Received-SPF: pass (spfCheck: domain of " + hostname + " designates 192.0.2.10 as permitted sender)"
            + " client-ip=192.0.2.10; envelope-from=\"a_user@" + hostname + "\"; helo=\"" + hostname + ".\";",
            result.getHeader());
    }

    @Test(timeout = 10000)
    public void shouldNotLookUpTheDomainUnderTheSearchPath() throws IOException {
        String hostname = "searchPath.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver(AnsweringResolver.withRcode(Rcode.NXDOMAIN));
        // the domain under a search path of the host, of a record that would pass
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + ".search.fake."), DClass.IN, 30L, "v=spf1 +all"));
        List<Name> searchPath = Lookup.getDefaultSearchPath();
        Lookup.setDefaultSearchPath(Name.fromString("search.fake."));
        try {
            SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));

            SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

            // RFC 7208 4.3: the domain is fully qualified, and does not exist
            assertEquals(SPFErrorConstants.NONE_CONV, result.getResult());
        } finally {
            Lookup.setDefaultSearchPath(searchPath);
        }
    }

    @Test(timeout = 10000)
    public void shouldReturnPermErrorOnAIp4CidrOverflowingAnInt() throws IOException {
        SPFResult result = checkRecord("aIp4CidrOverflow.spfexecutor.fake", "v=spf1 a/4294967296 -all", "1.2.3.4");

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnPermErrorOnMxIp6CidrOverflowingAnInt() throws IOException {
        SPFResult result = checkRecord("mxIp6CidrOverflow.spfexecutor.fake", "v=spf1 mx//99999999999 -all", "1.2.3.4");

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void mxShouldMatchAfterAnMxWhoseHostsHaveNoAddress() throws IOException {
        String hostname = "mxAfterMxWithoutAddress.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(new TXTRecord(Name.fromString(hostname + "."), DClass.IN, 30L,
            "v=spf1 mx:a." + hostname + " mx:b." + hostname + " -all"));
        fakeResolver.addRecord(new MXRecord(Name.fromString("a." + hostname + "."), DClass.IN, 30L, 10,
            Name.fromString("mail.a." + hostname + ".")));
        fakeResolver.addRecord(new MXRecord(Name.fromString("b." + hostname + "."), DClass.IN, 30L, 10,
            Name.fromString("mail.b." + hostname + ".")));
        fakeResolver.addRecord(new ARecord(Name.fromString("mail.b." + hostname + "."), DClass.IN, 30L,
            InetAddress.getByName("192.0.2.10")));

        SPFResult result = createCustomSPF(new DNSServiceXBillImpl(fakeResolver))
            .checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void mxShouldMatchAfterAnMxOfADomainWithoutMx() {
        DNSService dns = new DNSService() {
            public List<String> getRecords(DNSRequest request) {
                switch (request.getRecordType()) {
                    case DNSRequest.TXT:
                        return request.getHostname().equals("example.com")
                            ? new ArrayList<>(List.of("v=spf1 mx:nomx.example.com mx -all")) : null;
                    case DNSRequest.MX:
                        return request.getHostname().equals("example.com")
                            ? new ArrayList<>(List.of("mail.example.com")) : null;
                    case DNSRequest.A:
                        return request.getHostname().equals("mail.example.com")
                            ? new ArrayList<>(List.of("192.0.2.10")) : null;
                    default:
                        return null;
                }
            }

            // as DNSServiceXBillImpl: an asynchronous lookup without data fails
            public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
                List<String> records = getRecords(request);
                if (records == null) {
                    CompletableFuture<List<String>> noData = new CompletableFuture<>();
                    noData.completeExceptionally(new NoSuchRRSetException(Name.root, Type.MX));
                    return noData;
                }
                return CompletableFuture.completedFuture(records);
            }

            public List<String> getLocalDomainNames() {
                return List.of("localhost");
            }

            public void setTimeOut(int timeOut) {
            }

            public int getRecordLimit() {
                return 10;
            }

            public void setRecordLimit(int recordLimit) {
            }
        };

        SPFResult result = createCustomSPF(dns).checkSPF("192.0.2.10", "foo@example.com", "example.com");

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupError() throws IOException {
        String hostname = "unexpectedError.spfexecutor.fake";
        SPFResult result = checkRecordWithBrokenHost(hostname, "v=spf1 a:broken." + hostname + " -all");

        // RFC 7208 4.4: a DNS error "other than 0 or 3" ends the check as temperror
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheLookupServiceThrows() throws IOException {
        String hostname = "throwingLookup.spfexecutor.fake";
        SPFResult result = checkRecordWithThrowingHost(hostname, "v=spf1 a:broken." + hostname + " -all");

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnAnswerDnsjavaCannotNormalize() throws IOException {
        String hostname = "x.dname.spfexecutor.fake";
        // two DNAME records of a parent of the name queried: invalid zone data (RFC 6672 2.4)
        Message answer = new Message();
        answer.getHeader().setFlag(Flags.QR);
        answer.addRecord(new DNAMERecord(Name.fromString("dname.spfexecutor.fake."), DClass.IN, 30L,
            Name.fromString("a.example.")), Section.ANSWER);
        answer.addRecord(new DNAMERecord(Name.fromString("dname.spfexecutor.fake."), DClass.IN, 30L,
            Name.fromString("b.example.")), Section.ANSWER);
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(new AnsweringResolver(answer.toWire())));

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorInAnInclude() throws IOException {
        String hostname = "unexpectedErrorInInclude.spfexecutor.fake";
        SPFResult result = checkRecordWithBrokenHost(hostname, "v=spf1 include:broken." + hostname + " -all");

        // RFC 7208 5.2: a temperror of the included record is the result
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorInARedirect() throws IOException {
        String hostname = "unexpectedErrorInRedirect.spfexecutor.fake";
        SPFResult result = checkRecordWithBrokenHost(hostname, "v=spf1 redirect=broken." + hostname);

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void includeOfARecordWithoutTermShouldNotMatch() throws IOException {
        // RFC 7208 4.5: "v=spf1" is a record without terms, of result neutral (4.7)
        SPFResult result = checkRecordWithTarget("includeWithoutTerm.spfexecutor.fake", "v=spf1 include:%s -all", "v=spf1");

        // RFC 7208 5.2: an included neutral does not match
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void includeOfARecordWithoutDirectiveShouldNotMatch() throws IOException {
        SPFResult result = checkRecordWithTarget("includeWithoutDirective.spfexecutor.fake", "v=spf1 include:%s -all",
            "v=spf1 exp=explain.example.com");

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void redirectToARecordWithoutTermShouldBeNeutral() throws IOException {
        SPFResult result = checkRecordWithTarget("redirectWithoutTerm.spfexecutor.fake", "v=spf1 redirect=%s", "v=spf1");

        // RFC 7208 6.1: the result of the redirect target
        assertEquals(SPFErrorConstants.NEUTRAL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldReturnPermErrorOnLongInvalidTopLabel() throws IOException {
        String hostname = "shouldReturnPermErrorOnLongInvalidTopLabel.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        // a toplabel of 50000 letters, then "!", which no toplabel holds: no term matches
        fakeResolver.addRecord(longTxtRecord(hostname, "v=spf1 include:x." + "a".repeat(50000) + "! -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void defaultExplanationShouldNameTheCheckedDomainAfterAFailingInclude() throws IOException {
        String hostname = "defaultExplanationAfterFailingInclude.spfexecutor.fake";
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(includeOfAFailingRecord(hostname, "-all")));
        spf.setDefaultExplanation("Denied %{d}");

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
        assertEquals("Denied " + hostname, result.getExplanation());
    }

    @Test(timeout = 10000)
    public void passShouldHaveNoExplanationAfterAFailingInclude() throws IOException {
        String hostname = "passAfterFailingInclude.spfexecutor.fake";
        SPF spf = createCustomSPF(new DNSServiceXBillImpl(includeOfAFailingRecord(hostname, "+all")));
        spf.setDefaultExplanation("Denied %{d}");

        SPFResult result = spf.checkSPF("192.0.2.10", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
        // SPFResult gives "" when there is no explanation
        assertEquals("", result.getExplanation());
    }

    @Test(timeout = 10000)
    public void shouldTruncateALongExpandedIncludeTarget() throws IOException {
        // 225 characters and 102 dots, expanded 8000 times: the include target is close to 2 MB before
        // its truncation to a subdomain of hostname, with no record
        String hostname = "a.".repeat(100) + "truncate.spfexecutor.fake";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(longTxtRecord(hostname, "v=spf1 include:" + "%{d}.".repeat(8000) + hostname + " -all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        assertEquals(SPFErrorConstants.PERM_ERROR_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldTruncateAnIncludeTargetOf254CharactersTo253() throws IOException {
        String hostname = "includeTargetOf254Characters.spfexecutor.fake";
        // 252 characters, the include target without its first label, under hostname: FakeResolver answers it
        String target = "bb." + "b.".repeat(102) + hostname;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(longTxtRecord(hostname, "v=spf1 include:a." + target + " -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(target + "."), DClass.IN, 30L, "v=spf1 +all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        // RFC 7208 7.3: the left side is truncated to 253 characters, the longest domain name
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldKeepAnIncludeTargetOf253CharactersAndATrailingDot() throws IOException {
        String hostname = "includeTargetWithTrailingDot.spfexecutor.fake";
        // 253 characters, the longest domain name, under hostname: FakeResolver answers it, cut or not
        String target = "ccc." + "b.".repeat(102) + hostname;
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.addRecord(longTxtRecord(hostname, "v=spf1 include:" + target + ". -all"));
        fakeResolver.addRecord(new TXTRecord(Name.fromString(target + "."), DClass.IN, 30L, "v=spf1 +all"));

        SPF spf = createCustomSPF(new DNSServiceXBillImpl(fakeResolver));
        SPFResult result = spf.checkSPF("1.2.3.4", "a_user@" + hostname, hostname);

        // RFC 7208 7.3: 253 characters "in this format", without the trailing dot of a fully qualified name
        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult());
    }
}
