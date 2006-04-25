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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;

import org.xbill.DNS.Address;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * This class contains helper to get all neccassary DNS infos that are needed for SPF
 * 
 * @author MimeCast
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class DNSProbe {

	/**
	 * Get the SPF-Record for a server given it's version
	 *  
	 * TODO: support SPF Records too.
	 * 
	 * @param hostname The hostname for which we want to retrieve the SPF-Record
	 * @param spfVersion The SPF-Version which should used.
	 * @return The SPF-Record if one is found.
	 * @throws ErrorException if more then one SPF-Record was found.
	 * @throws NoneException if no SPF-Record was found.
	 * @throws NeutralException if an invalid SPF-Version was specified.
	 */
	protected static String getSpfRecord(String hostname, String spfVersion)
			throws ErrorException, NeutralException, NoneException {

		String returnValue = null;
		ArrayList txtR = new ArrayList();

		// do DNS lookup for TXT
		txtR = getTXTRecords(hostname);

		// process returned records
		if (!txtR.isEmpty()) {

			Iterator all = txtR.iterator();

			while (all.hasNext()) {
				String compare = all.next().toString().trim();

				// remove '"'
				compare = compare.toLowerCase().substring(1,
						compare.length() - 1);

				if (compare.startsWith(spfVersion + " ")) {
					if (returnValue == null) {
						returnValue = compare;
					} else {
						throw new ErrorException("More than 1 SPF record found");
					}
				}
			}
		}
		if (returnValue == null) {
			throw new NoneException("No SPF record found");
		}
		return returnValue;
	}

	/**
	 * Get an ArrayList of all TXT Records for a partical domain.
	 *  
	 * @param hostname The hostname for which the TXT-Records should be retrieved
	 * @return TXT Records-which were found. 
	 * @throws NoneException if none TXT-Records were found.
	 * @throws ErrorException  
	 */
	public static ArrayList getTXTRecords(String hostname)
			throws NoneException, ErrorException {
		ArrayList txtR = new ArrayList();
		Record[] records;
		try {
			records = new Lookup(hostname, Type.TXT).run();
			if (records != null) {
				for (int i = 0; i < records.length; i++) {
					TXTRecord txt = (TXTRecord) records[i];
					txtR.add(txt.rdataToString());
				}
			} else {
				throw new NoneException("No TXTRecord found");
			}
		} catch (TextParseException e) {
			//I think thats the best we could do
			throw new NoneException("No TXTRecord found");
		}
		return txtR;
	}

	/**
	 * Check if a the given domain could be resolved (is FQDN)
	 * 
	 * @param domain The domain which should be resolved
	 * @return false or true
	 */
	public static boolean isFQDN(String domain) {
		boolean isResolvable = true;

		try {
			Address.getByName(domain);
		} catch (UnknownHostException e) {
			isResolvable = false;
		}
		return isResolvable;
	}

	/**
	 * 
	 * @see #getARecords(String strServer, int mask)
	 */
	public static ArrayList getARecords(String strServer)
			throws NeutralException, NoneException, ErrorException {
		return getARecords(strServer, 32);
	}

	/**
	 * Get a list of IPAddr's for a server using the mask length
	 * 
	 * @param strServer The hostname or ipAddress whe should get the A-Records for
	 * @param mask The netmask to use
	 * @return The ipAddresses
	 * @throws NeutralException
	 * @throws NoneException if no A records was found 
	 * @throws ErrorException
	 */
	public static ArrayList getARecords(String strServer, int mask)
			throws NeutralException, NoneException, ErrorException {

		String host = null;
		ArrayList listTxtData = new ArrayList();

		if (IPAddr.isIPAddr(strServer)) {
			try {
				IPAddr ipTest = IPAddr.getAddress(strServer);
				// Address is already an IP address, so add it to list
				listTxtData.add(ipTest);
			} catch (NeutralException e1) {
				throw new NeutralException(e1.getMessage());
			}
		} else {
			try {
				// do DNS A lookup
				InetAddress[] hosts = Address.getAllByName(strServer);

				// process returned records
				for (int i = 0; i < hosts.length; i++) {

					host = hosts[i].getHostAddress();

					if (host != null) {
						ArrayList ipArray = getIPList(host, mask);
						Iterator ip = ipArray.iterator();

						while (ip.hasNext()) {
							listTxtData.add(ip.next());
						}
					}

				}

			} catch (UnknownHostException e1) {
				throw new NoneException("No A record found");
			}
		}
		return listTxtData;
	}

	/**
	 * Convert list of DNS names to masked IPAddr
	 *
	 * @param addressList ArrayList of DNS names which should be converted to masked IPAddresses
	 * @param maskLength the networkmask
	 * @return ArrayList of the conversion
	 * @throws ErrorException
	 */
	protected static ArrayList getAList(ArrayList addressList, int maskLength)
			throws ErrorException {

		ArrayList listAddresses = new ArrayList();
		String aValue;

		for (int i = 0; i < addressList.size(); i++) {
			aValue = addressList.get(i).toString();
			try {
				listAddresses.addAll(DNSProbe.getARecords(aValue, maskLength));
			} catch (Exception e) {
				// Carry on regardless?
			}
		}
		return listAddresses;
	}

	/**
	 * Get TXT records as a string
	 * @param strServer The hostname for which we want to retrieve the TXT-Record
	 * @return String which reflect the TXT-Record
	 * @throws NoneException if no TXT-Record was found 
	 * @throws ErrorException if the hostname is not resolvable
	 */
	public static String getTxtCatType(String strServer) throws NoneException,
			ErrorException {

		StringBuffer txtData = new StringBuffer();
		ArrayList records = getTXTRecords(strServer);
		for (int i = 0; i < records.size(); i++) {
			txtData.append(records.get(i));
		}
		return txtData.toString();
	}

	/**
	 * Get reverse DNS records
	 * 
	 * @param ipAddress The ipAddress for which we want to get the PTR-Record
	 * @return the PTR-Records
	 * @throws NoneException if no PTR-Record was found
	 * 
	 */

	public static ArrayList getPTRRecords(String ipAddress)
			throws ErrorException, NoneException, NeutralException {

		ArrayList ptrR = new ArrayList();
		Record[] records;

		// do DNS lookup for TXT
		IPAddr ip;
		try {
			ip = IPAddr.getAddress(ipAddress);

			try {
				records = new Lookup(ip.getReverseIP() + ".in-addr.arpa",
						Type.PTR).run();
				if (records != null) {
					for (int i = 0; i < records.length; i++) {
						PTRRecord ptr = (PTRRecord) records[i];
						ptrR.add(IPAddr.stripDot(ptr.getTarget().toString()));
						System.out.println("IP = "
								+ IPAddr.stripDot(ptr.getTarget().toString()));
					}
				} else {
					throw new NoneException("No PTRRecord found");
				}
			} catch (TextParseException e) {
				// i think this is the best we could do
				throw new NoneException("No PTRRecord found");
			}
		} catch (NeutralException e1) {
			throw new NeutralException(e1.getMessage());
		}
		return ptrR;
	}

	/**
	 * 
	 * @see #getMXRecords(String domainName, int mask, boolean stripInvalidMX)
	 */
	public static ArrayList getMXRecords(String domainName,
			boolean stripInvalidMX) throws NoneException, ErrorException {
		return getMXRecords(domainName, 32, stripInvalidMX);
	}

	/**
	 * Get a list of masked IPAddr MX-Records
	 * 
	 * TODO: Check if stripInvalidMX should be removed. I see no need for this.
	 *  
	 * @param domainName The domainName or ipaddress we want to get the ips for
	 * @param mask The netmask
	 * @param stripInvalidMX Strip mxrecords which belongs to reserved nerworks
	 * @return IPAddresses of the MX-Records
	 * @throws NoneException if no MX-Record was found
	 * @throws ErrorException
	 */
	public static ArrayList getMXRecords(String domainName, int mask,
			boolean stripInvalidMX) throws ErrorException, NoneException {

		ArrayList mxAddresses = DNSProbe.getAList(DNSProbe
				.getMXNames(domainName), mask);

		if (stripInvalidMX == true) {
			return stripInvalidMX(mxAddresses);
		} else {
			return mxAddresses;
		}
	}

	/**
	 * Strip invalid ips (reserved ips) from MX-Records
	 * 
	 * TODO: Do we really need this. I don't think so!
	 * 
	 * @param mxAddresses ArrayList which contains the MXrecords
	 * @return Valid MXRecords
	 */
	private static ArrayList stripInvalidMX(ArrayList mxAddresses) {

		String address;
		IPAddr tempAddress;
		int size = mxAddresses.size();

		for (int i = 0; i < size; i++) {

			tempAddress = (IPAddr) mxAddresses.get(size - 1 - i);
			address = tempAddress.getIPAddress();

			if (ReservedMX.isReserved(address)) {
				mxAddresses.remove(size - 1 - i);
			}

		}

		return mxAddresses;

	}

	/**
	 * Get an ArrayList of IPAddr's given the DNS type and mask
	 * 
	 * @param host The hostname or ip of the server for which we want to get the ips
	 * @param mask The netmask
	 * @return ipAddresses
	 */
	private static ArrayList getIPList(String host, int mask)
			throws ErrorException {

		ArrayList listIP = new ArrayList();

		try {
			if (host != null) {
				listIP.addAll(IPAddr.getAddresses(host, mask));
			}
		} catch (Exception e1) {
			throw new ErrorException(e1.getMessage());
		}

		return listIP;

	}

	/**
	 * Get all MX Records for a domain
	 * 
	 * @param host The hostname we want to retrieve the MXRecords for
	 * @return MX-Records for the given hostname
	 * @throws NoneException if no MX-Records was found
	 */
	public static ArrayList getMXNames(String host) throws NoneException {
		ArrayList mxR = new ArrayList();
		Record[] records;
		try {
			records = new Lookup(host, Type.MX).run();
			if (records != null) {
				for (int i = 0; i < records.length; i++) {
					MXRecord mx = (MXRecord) records[i];
					mxR.add(mx.getTarget());

				}
			} else {
				throw new NoneException("No MX Record");
			}
		} catch (TextParseException e) {
			// i think this is the best we could do
			throw new NoneException("No MX Record");
		}
		return mxR;
	}
	
	public static String getARecord(String host) throws NoneException {
		String rec = null;
		
		try {
			rec = Address.getByName(host).getHostAddress();
			System.err.println("REC: " +rec);
		} catch (UnknownHostException e) {
			throw new NoneException("No A record found");
		}
		return rec;
	}
}
