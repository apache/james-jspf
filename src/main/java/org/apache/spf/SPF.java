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
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */

public class SPF {

    private DNSService dnsProbe = null;

    private SPF1Data spfData;

    private String explanation = "";

    private String headerTextAsString = "";

    private String headerName = "Received-SPF";

    private String header = "";

    private SPF1Parser parser;

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
        this.parser = new SPF1Parser();
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

        String result = null;

        spfData = null;
        try {
            // Setup the data
            spfData = new SPF1Data(mailFrom, hostName, ipAddress, dnsProbe);
            result = checkSPF(spfData);
        } catch (PermErrorException e) {
            e.printStackTrace();
            result = SPF1Utils.PERM_ERROR;
        } catch (NoneException e) {
            e.printStackTrace();
            result = SPF1Utils.NONE;
        } catch (TempErrorException e) {
            e.printStackTrace();
            result = SPF1Utils.TEMP_ERROR;
        }

        // convert raw result to name
        String convertedResult = SPF1Utils.resultToName(result);

        // generate the SPF-Result header
        generateHeader(convertedResult);

        return convertedResult;

    }

    /**
     * @param ipAddress
     * @throws PermErrorException
     * @throws NoneException
     * @throws TempErrorException
     */
    public String checkSPF(SPF1Data spfData) throws PermErrorException, NoneException, TempErrorException {
        String result;
        result = SPF1Utils.NEUTRAL;

        /**
         * Check if the connection was made from localhost. Set the result to
         * PASS if its from localhost.
         */
        if (spfData.getIpAddress().trim().startsWith("127.")) {
            result = SPF1Utils.PASS;
            return result;
        }

        // Get the raw dns txt entry which contains a spf entry
        String spfDnsEntry = dnsProbe.getSpfRecord(spfData
                .getCurrentDomain(), SPF1Utils.SPF_VERSION);

        System.out.println(spfDnsEntry);

        SPF1Record spfRecord = parser.parse(spfDnsEntry);
        
        System.out.println(spfRecord);

        boolean match = false;
        String qualifier = null;
        boolean hasCommand = false;

        // get all commands
        Iterator com = spfRecord.getDirectives().iterator();
        while (com.hasNext()) {
            
            // if we reach maximum calls we must throw a PermErrorException. See SPF-RFC Section 10.1.  Processing Limits
            if (spfData.getCurrentDepth() > spfData.getMaxDepth()) {
                throw new PermErrorException("Maximum mechanism/modifier calls done: " + spfData.getCurrentDepth());
            }
            
            hasCommand = true;
            Directive d = (Directive) com.next();

            qualifier = d.run(spfData);
 
            if (qualifier != null) {
                if(qualifier.equals("")) {
                    result = SPF1Utils.PASS;
                } else {
                    result = qualifier;
                }
                match = true;
                // If we have a match we should break the while loop
                break;
            }
        }
        
        Iterator mod = spfRecord.getModifiers().iterator();
        while (mod.hasNext()) {
            spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);
            
            // if we reach maximum calls we must throw a PermErrorException. See SPF-RFC Section 10.1.  Processing Limits
            if (spfData.getCurrentDepth() > spfData.getMaxDepth()) {
                throw new PermErrorException("Maximum mechanism/modifiers calls done: " + spfData.getCurrentDepth());
            }
            
            Modifier m = (Modifier) mod.next();
            
            String q = m.run(spfData);
            if (q != null) {
                qualifier = q;
            }

            if (qualifier != null) {
                result = qualifier;
                
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
        return result;
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

        String ipAddress = "192.0.2.120";
        String mailFrom = "20.spf1-test.mailzone.com";
        String host = "20.spf1-test.mailzone.com";

        // run test !
        String result = spf.checkSPF(ipAddress, mailFrom, host);

        System.out.println("result:     " + result);
        System.out.println("header:     " + spf.getHeader());
        System.out.println("exp:        " + spf.getExplanation());

    }

}
