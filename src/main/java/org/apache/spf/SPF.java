/***********************************************************************
 * Copyright (c) 1999-2006 The Apache Software Foundation.             *
 * All rights reserved.                                                *
 * ------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License"); you *
 * may not use this file except in compliance with the License. You    *
 * may obtain a copy of the License at:                                *
 *                                                                     *
 *     http://www.apache.org/licenses/LICENSE-2.0                      *
 *                                                                     *
 * Unless required by applicable law or agreed to in writing, software *
 * distributed under the License is distributed on an "AS IS" BASIS,   *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or     *
 * implied.  See the License for the specific language governing       *
 * permissions and limitations under the License.                      *
 ***********************************************************************/

package org.apache.spf;

import org.apache.spf.mechanismn.Directive;
import org.apache.spf.modifier.Modifier;

import java.util.Iterator;

/**
 * This class is used to generate a SPF-Test and provided all intressting data.
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

public class SPF {

    private DNSService dnsProbe = null;

    private SPF1Data spfData;

    private String explanation = "";

    private String headerTextAsString = "";

    private String headerName = "Received-SPF";

    private String header = "";

    /**
     * 
     */
    public SPF() {
        this(new DNSServiceXBillImpl());
    }

    /**
     * @param dnsProbe
     *            the dns provider
     */
    public SPF(DNSService dnsProbe) {
        super();
        this.dnsProbe = dnsProbe;
    }

    /**
     * Run check for SPF with the given values.
     * 
     * @param ipAddress
     *            The ipAddress the connection is comming from
     * @param mailFrom
     *            The mailFrom which was provided
     * @param hostName
     *            The hostname which was provided as HELO/EHLO
     * @return result. Possible results are: pass, neutral, fail, deny,
     *         softfail, error, none
     */
    public String checkSPF(String ipAddress, String mailFrom, String hostName) {

        // TODO is the default PASS ?
        String result = SPF1Utils.PASS;
        
        /**
         * Check if the connection was made from localhost. Set the result to
         * PASS if its from localhost.
         */
        if (ipAddress.trim().startsWith("127.")) {
            result = SPF1Utils.PASS;
            return SPF1Utils.resultToName(result);
        }

        spfData = null;

        try {
            // Setup the data
            spfData = new SPF1Data(mailFrom, hostName, ipAddress, dnsProbe);

            // Get the raw dns txt entry which contains a spf entry
            String spfDnsEntry = dnsProbe.getSpfRecord(spfData
                    .getCurrentDomain(), SPF1Utils.SPF_VERSION);

            // Parse the record
            SPF1Record spfRecord = new SPF1Parser().parse(spfDnsEntry);

            boolean match = false;
            String qualifier = null;
            boolean hasCommand = false;

            // get all commands
            Iterator com = spfRecord.getDirectives().iterator();
            while (com.hasNext()) {
                hasCommand = true;
                Directive d = (Directive) com.next();

                qualifier = d.run(spfData);
 
                if (qualifier != null) {
                    match = true;
                }
            }
            
            Iterator mod = spfRecord.getModifiers().iterator();
            while (mod.hasNext()) {
                Modifier m = (Modifier) mod.next();
                
                String q = m.run(spfData);
                if (q != null) {
                    qualifier = q;
                }

                if (qualifier != null) {
                    if (qualifier.equals(SPF1Utils.FAIL)) {
                        explanation = spfData.getExplanation();
                    }
                }

            }

            // If no match was found set the result to neutral 
            if ((match == false) && (hasCommand == true)) {
                result = SPF1Utils.NEUTRAL;
            }
            // Catch the exceptions and set the result
            // TODO: remove printStackTrace() if all was checked and works!

        } catch (PermErrorException e) {
            e.printStackTrace();
            result = SPF1Utils.ERROR;
        } catch (NoneException e) {
            e.printStackTrace();
            result = SPF1Utils.NONE;
        }

        // convert raw result to name
        String convertedResult = SPF1Utils.resultToName(result);

        // generate the SPF-Result header
        generateHeader(convertedResult);

        return convertedResult;

    }

    /**
     * Get the explanation. The explanation is only set if the result is "-" =
     * fail
     * 
     * @return explanation
     */
    public String getExplanation() {
        return explanation;
    }

    /**
     * Get the full SPF-Header (headername and headertext)
     * 
     * @return SPF-Header
     */
    public String getHeader() {
        return header;
    }

    /**
     * Get the SPF-Headername
     * 
     * @return headername
     */
    public String getHeaderName() {
        return headerName;
    }

    /**
     * Get SPF-Headertext
     * 
     * @return headertext
     */
    public String getHeaderText() {
        return headerTextAsString;
    }

    /**
     * Generate a SPF-Result header
     * 
     * @param result
     *            The result we should use to generate the header
     */
    private void generateHeader(String result) {

        StringBuffer headerText = new StringBuffer();

        if (result.equals(SPF1Utils.PASS_CONV)
                || result.equals(SPF1Utils.ALLOW_CONV)) {
            headerText.append(result + " (spfCheck: domain of "
                    + spfData.getCurrentDomain() + " designates "
                    + spfData.getIpAddress() + " as permitted sender) ");
        } else if (result.equals(SPF1Utils.FAIL_CONV)
                || result.equals(SPF1Utils.DENY_CONV)) {
            headerText.append(result + " (spfCheck: domain of "
                    + spfData.getCurrentDomain() + " does not designate "
                    + spfData.getIpAddress() + " as permitted sender) ");
        } else if (result.equals(SPF1Utils.NEUTRAL_CONV)
                || result.equals(SPF1Utils.NONE_CONV)) {
            headerText.append(result + " (spfCheck: " + spfData.getIpAddress()
                    + " is neither permitted nor denied by domain of "
                    + spfData.getCurrentDomain() + ") ");

        } else if (result.equals(SPF1Utils.SOFTFAIL_CONV)) {
            headerText.append(result + " (spfCheck: transitioning domain of "
                    + spfData.getCurrentDomain() + " does not designate "
                    + spfData.getIpAddress() + " as permitted sender) ");
        }

        if (headerText.length() > 0) {
            headerText.append("client-ip=" + spfData.getIpAddress()
                    + "; envelope-from=" + spfData.getMailFrom() + "; helo="
                    + spfData.getHostName() + ";");
            headerTextAsString = headerText.toString();
        }
        header = headerName + ": " + headerTextAsString;
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
        SPF spf = new SPF();

        String ipAddress = "192.168.200.1";
        String mailFrom = "nm@aol.com";
        String host = "aol.com";

        // run test !
        String result = spf.checkSPF(ipAddress, mailFrom, host);

        System.out.println("result:     " + result);
        System.out.println("header:     " + spf.getHeader());
        System.out.println("exp:        " + spf.getExplanation());

    }

}
