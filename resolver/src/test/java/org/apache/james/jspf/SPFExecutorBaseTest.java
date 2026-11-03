package org.apache.james.jspf;

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.helpers.FakeResolver;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.SPF;
import org.apache.james.jspf.policies.local.TrustedForwarderPolicy;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SPFRecord;
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
                        "Received-SPF: %3$s (spfCheck: domain of x\\)client-ip=203.0.113.9;\\(.%2$s does not designate %1$s as permitted sender) client-ip=%1$s; envelope-from=a_user@%2$s; helo=%2$s;",
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
    public void shouldEndAsNeutralOnAnUnexpectedLookupErrorInAnInclude() throws IOException {
        String hostname = "unexpectedErrorInInclude.spfexecutor.fake";
        SPFResult result = checkRecordWithBrokenHost(hostname, "v=spf1 include:broken." + hostname + " -all");

        // as at the top level, the exception catcher of SPF makes the unexpected error neutral
        assertEquals(SPFErrorConstants.NEUTRAL_CONV, result.getResult());
    }

    @Test(timeout = 10000)
    public void shouldEndAsNeutralOnAnUnexpectedLookupErrorInARedirect() throws IOException {
        String hostname = "unexpectedErrorInRedirect.spfexecutor.fake";
        SPFResult result = checkRecordWithBrokenHost(hostname, "v=spf1 redirect=broken." + hostname);

        assertEquals(SPFErrorConstants.NEUTRAL_CONV, result.getResult());
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
