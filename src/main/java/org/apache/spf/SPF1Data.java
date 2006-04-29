/**********************************************************************
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

import java.util.List;

import org.apache.spf.util.IPAddr;

/**
 * 
 * This Class is used as a Container between the other classes.
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

public class SPF1Data {
    
    private DNSService dnsProbe = null;

	protected String spfVersion = "v=spf1";

	private String ipAddress = ""; // (i)<sending-host>

	private String mailFrom = ""; // (s)<responsible-sender>

	private String hostName = ""; // (h)<sender-domain>

	private String currentSenderPart = ""; // (l)

	private String currentDomain = ""; // (d)<current-domain>

	private String inAddress = "in-addr"; // (v)

	private String clientDomain = ""; // (p)

	private String senderDomain = ""; // (o)

	private long timeStamp = System.currentTimeMillis(); // (t)

	private String readableIP = ""; // (c)

	private String receivingDomain = "unknown"; // (r)

	private int depth = 1;

    protected SPF1Data(String mailFrom, String heloDomain, String clientIP)
            throws PermErrorException, NoneException {
        this(mailFrom, heloDomain, clientIP, new DNSServiceXBillImpl());
    }

	protected SPF1Data(String mailFrom, String heloDomain, String clientIP, DNSService dnsProbe)
			throws PermErrorException, NoneException {

		this.mailFrom = mailFrom.trim();
		this.hostName = heloDomain.trim();
		this.ipAddress = clientIP.trim();
        this.dnsProbe = dnsProbe;

		try {
			// get the in Address
			inAddress = IPAddr.getInAddress(clientIP);
		} catch (PermErrorException e) {
			// throw an exception cause the ip was not rfc conform
			throw new PermErrorException(e.getMessage());
		}

		// setup the data!
		setupData(mailFrom, hostName);
	}

	/**
	 * Setup the data which used to retrieve the SPF-Record
	 * 
	 * @throws NoneException
	 *             if no valid emailaddress is provided
	 */
	private void setupData(String mailFrom, String hostName)
			throws NoneException {

		// if nullsender is used postmaster@helo will be used as email
		if (mailFrom.equals("")) {
			this.currentSenderPart = "postmaster";
			this.senderDomain = hostName;
			this.mailFrom = currentSenderPart + "@" + hostName;
		} else {
			String[] fromParts = mailFrom.split("@");

			// should never be bigger as 2 !
			if (fromParts.length > 2) {
				throw new NoneException("Not a valid email address " + mailFrom);
			} else if (fromParts.length == 2) {
				this.currentSenderPart = fromParts[0];
				this.senderDomain = fromParts[1];
			} else {
				this.currentSenderPart = "postmaster";
				this.senderDomain = mailFrom;
			}
		}
		this.currentDomain = this.senderDomain;
	}

	/**
	 * Get current-senderpart (l)
	 * 
	 * @return current-senderpart
	 */
	public String getCurrentSenderPart() {
		return currentSenderPart;
	}

	/**
	 * Get responsible-sender (s)
	 * 
	 * @return responsible-sender
	 */
	public String getMailFrom() {
		return mailFrom;
	}

	/**
	 * Get sender-domain (h)
	 * 
	 * @return sender-domain
	 */
	public String getHostName() {
		return hostName;
	}

	/**
	 * Get current-domain (d)
	 * 
	 * @return current-domain
	 */
	public String getCurrentDomain() {
		return currentDomain;
	}

	/**
	 * Get inAddress (v)
	 * 
	 * @return inAddress
	 */
	public String getInAddress() {
		return inAddress;
	}

	/**
	 * Get clientDomain (p)
	 * 
	 * @return clientDomain
	 */
	public String getClientDomain() {
		List domains;
		try {
			domains = dnsProbe.getPTRRecords(ipAddress);
			if (domains.size() > 0) {
				clientDomain = (String) domains.get(0);
			} else {
				clientDomain = ipAddress;
			}
		} catch (Exception e) {
			clientDomain = ipAddress;
		}
		return clientDomain;
	}

	/**
	 * Get senderDomain (o)
	 * 
	 * @return senderDomain
	 */
	public String getSenderDomain() {
		return senderDomain;
	}

	/**
	 * Get sending-host (i)
	 * 
	 * @return sending-host
	 */
	public String getIpAddress() {
		return ipAddress;
	}

	/**
	 * Get timeStamp (t)
	 * 
	 * @return timeStamp
	 */
	public long getTimeStamp() {
		return timeStamp;
	}

	/**
	 * Get readableIP (c)
	 * 
	 * @return readableIP
	 */
	public String getReadableIP() {
		return readableIP;
	}

	/**
	 * Get receivingDomain (r)
	 * 
	 * @return receivingDomain
	 */
	public String getReceivingDomain() {
		return receivingDomain;
	}

	/**
	 * Get Depth
	 * 
	 * @return depth
	 */
	public int getDepth() {
		return depth;
	}

	/**
	 * Set Depth
	 * 
	 * @param depth
	 */
	public void setDepth(int depth) {
		this.depth = depth;
	}

	/**
	 * Set the currentDomain
	 * 
	 * @param domain
	 */
	public void setCurrentDomain(String domain) {
		this.currentDomain = domain;
	}

    public DNSService getDnsProbe() {
        return dnsProbe;
    }

    public void setDnsProbe(DNSService dnsProbe) {
        this.dnsProbe = dnsProbe;
    }


}