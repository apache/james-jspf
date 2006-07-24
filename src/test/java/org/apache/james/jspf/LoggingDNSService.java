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


package org.apache.james.jspf;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LoggingDNSService implements DNSService {
    
    private DNSService dnsService = new DNSServiceXBillImpl(new ConsoleLogger());

    public String getSpfRecord(String hostname, String spfVersion)
            throws PermErrorException, NoneException, TempErrorException {
        try {
            String res = dnsService.getSpfRecord(hostname, spfVersion);

            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = " + res);
            return res;
        } catch (TempErrorException e) {
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }
    }

    public List getLocalDomainNames() {
        List res = dnsService.getLocalDomainNames();
        System.out.print("getLocalDomainNames() = ");
        if (res != null) {
            for (int i = 0; i < res.size(); i++) {
                System.out.print(res.get(i));
                if (i == res.size() - 1) {
                    System.out.println("");
                } else {
                    System.out.print(",");
                }
            }
        } else {
            System.out.println("getLocalDomainNames-ret: null");
        }
        return res;

    }

    public List getAAAARecords(String strServer, int mask)
            throws NoneException, PermErrorException, TempErrorException {

        try {
            List res = dnsService.getAAAARecords(strServer, mask);
            System.out.print("getAAAARecords(" + strServer + "," + mask
                    + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("getAAAARecords-ret: null");
            }
            return res;

        } catch (TempErrorException e) {
            System.out.println("getAAAARecords(" + strServer + "," + mask
                    + ") = TermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getAAAARecords(" + strServer + "," + mask
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getAAAARecords(" + strServer + "," + mask
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }
    }

    public List getARecords(String strServer, int mask) throws NoneException,
            PermErrorException, TempErrorException {
        try {
            List res = dnsService.getARecords(strServer, mask);
            System.out.print("getARecords(" + strServer + "," + mask + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("getARecords-ret: null");
            }
            return res;

        } catch (TempErrorException e) {
            System.out.println("getARecords(" + strServer + "," + mask
                    + ") = TermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getARecords(" + strServer + "," + mask
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getARecords(" + strServer + "," + mask
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public String getTxtCatType(String strServer) throws NoneException,
            PermErrorException, TempErrorException {
        try {
            String res = dnsService.getTxtCatType(strServer);
            System.out.println("getTxtCatType(" + strServer + ") = " + res);
            return res;
        } catch (TempErrorException e) {
            System.out.println("getTxtCatType(" + strServer
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getTxtCatType(" + strServer
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getTxtCatType(" + strServer
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public List getPTRRecords(String ipAddress) throws PermErrorException,
            NoneException, TempErrorException {
        try {
            List res = dnsService.getPTRRecords(ipAddress);
            System.out.print("getPTRRecords(" + ipAddress + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("null");
            }
            return res;
        } catch (TempErrorException e) {
            System.out.println("getPTRRecords(" + ipAddress
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getPTRRecords(" + ipAddress
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getPTRRecords(" + ipAddress
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public List getAddressList(String list, int mask) throws PermErrorException {
        if (list == null || "".equals(list)) {
            return new ArrayList();
        }
        String[] s = list.split(",");
        IPAddr[] ips = new IPAddr[s.length];
        for (int i = 0; i < s.length; i++) {
            ips[i] = IPAddr.getAddress(s[i], mask);
        }
        return new ArrayList(Arrays.asList(ips));
    }

    public List getMXRecords(String domainName, int mask)
            throws PermErrorException, NoneException, TempErrorException {
        try {
            List res = dnsService.getMXRecords(domainName, mask);
            System.out
                    .print("getMXRecords(" + domainName + "," + mask + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("null");
            }
            return res;
        } catch (TempErrorException e) {
            System.out.println("getMXRecords(" + domainName + "," + mask
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getMXRecords(" + domainName + "," + mask
                    + ") = ErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getMXRecords(" + domainName + "," + mask
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public void setTimeOut(int timeOut) {
        // MOCK
    }
}