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

/**
 * This class is used to process the diffrent SPF-Commands.
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

import java.util.ArrayList;

public class SPF1Command {

	protected static final String MODIFIERS = "+-?~";

	private String prefix = "+";

	private String command = "";

	private String suffix1 = "";

	private String suffix2 = "";

	private int maskLengthIP4 = 32;

	private int maskLengthIP6 = 128;

	private SPF1Data spfData;

	private boolean mechanism = true;

	protected SPF1Command(String rawCommand, SPF1Data spfData)
			throws NeutralException,UnknownException {

		this.spfData = spfData;
		if (rawCommand.length() == 0) {
			throw new NeutralException("Command must be a string");
		}
		if (MODIFIERS.indexOf(rawCommand.substring(0, 1)) > -1) {
			prefix = rawCommand.substring(0, 1);
			command = rawCommand.substring(1).trim();
		} else {
			command = rawCommand.trim();
		}

		if (!isSPF1Command()) {
			String[] temp = command.split("=");
			command = temp[0].toLowerCase().trim();

			// Create mechanism otherwise is an unknown SPF1 command
			if (temp.length == 2) {
				mechanism = false;
				suffix1 = temp[1].toLowerCase().trim();
			}
		}

		// Check for valid maskLengh. If its invalid throw an exception.
		if (maskLengthIP4 > 32 || maskLengthIP4 < 0) {
			throw new NeutralException("Invalid CIDR length near \"/"
					+ maskLengthIP4 + "\" in \"" + rawCommand + "\"");
			// throw new NeutralException("CIDR length out of bounds");
		} else if (maskLengthIP6 > 128 || maskLengthIP6 < 0) {
			throw new NeutralException("Invalid CIDR length near \"/"
					+ maskLengthIP6 + "\" in \"" + rawCommand + "\"");

		}
	}

	/***************************************************************************
	 * Get the command
	 * 
	 * @return command
	 */
	protected String getCommand() {
		return command;
	}

	/**
	 * Get the prefix
	 * 
	 * @return prefix
	 */
	protected String getPrefix() {
		return prefix;
	}

	/**
	 * Get the suffix
	 * 
	 * @return suffix
	 */
	protected String getSuffix() {
		return suffix1;
	}

	/**
	 * Return true if its a mechanism
	 * 
	 * @return true or false
	 */
	protected boolean isMechanism() {
		return mechanism;
	}

	/**
	 * Return true if the given command is the current command.
	 * 
	 * @param command
	 *            The current command
	 * @return true or false
	 */
	protected boolean isCommand(String command) {
		if (this.command.equals(command)) {
			return true;
		} else {
			return false;
		}
	}

	public String toString() {
		return prefix + " : " + command + " : " + suffix1 + " : " + suffix2;
	}

	/**
	 * Run the checkcommand for the A prefix
	 * 
	 * @param checkAddress
	 *            The ipAddress
	 * @param domainName
	 *            The domain
	 * @return true or false
	 * @throws ErrorException
	 *             if an error result should returned
	 * @throws UnknownException
	 *             if an unknown result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 * @throws WarningException
	 */
	protected boolean runACommand(IPAddr checkAddress, String domainName)
			throws NeutralException, ErrorException, NoneException,
			UnknownException {

		ArrayList addressList = new ArrayList();
		String domainData;

		checkAddress = IPAddr.getAddress(checkAddress.getIPAddress(),
				maskLengthIP4);

		if (suffix1.equals("")) {
			domainData = domainName;
		} else {
			domainData = suffix1;
		}
        
        System.out.println("SUF: " + domainData);

		// check if its a FQDN
		if (SPF1Utils.checkFQDN(domainData)) {
			addressList.addAll(DNSProbe.getARecords(domainData, maskLengthIP4));
			if (checkAddressList(checkAddress, addressList)) {
				return true;
			}
		} else {

			throw new UnknownException(
					"Warning: Hostname has a missing or invalid TLD");
		}
		return false;
	}

	/**
	 * Run the checkcommand for the MX prefix
	 * 
	 * @param checkAddress
	 *            The ipAddress
	 * @param domainName
	 *            -The domain
	 * @return true or false
	 * @throws ErrorException
	 *             if an error result should returned
	 * @throws UnknownException 
	 * @throws WarningException
	 * @throws UnknownException
	 *             if an unknown result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 */
	protected boolean runMXCommand(IPAddr checkAddress, String domainName)
			throws ErrorException, NeutralException, UnknownException {

		String domainData;

		checkAddress = IPAddr.getAddress(checkAddress.getIPAddress(),
				maskLengthIP4);

		if (suffix1.equals("")) {
			domainData = domainName;
		} else {

			domainData = suffix1;
		}

		// check if its a FQDN
		if (SPF1Utils.checkFQDN(domainData)) {
			try {
				if (checkAddressList(checkAddress, DNSProbe.getMXRecords(
						domainData, maskLengthIP4))) {
					return true;
				}

			} catch (NoneException e) {
			}
		} else {

			throw new UnknownException(
					"Warning: Hostname has a missing or invalid TLD");

		}
		return false;
	}

	/**
	 * Run the checkcommand for the IP prefix. Should work for both IP4 & IP6
	 * 
	 * @param ipAddress
	 *            The ipAddress
	 * @return true or false
	 * @throws NeutralException
	 *             if the result should be neutral
	 * @throws ErrorException 
	 */
	protected boolean runIPCommand(String ipAddress) throws NeutralException,
			ErrorException {

		if (IPAddr.isValidIP(suffix1) == false) {
			throw new ErrorException("Not a valid IP address: " + suffix1);
		}
		IPAddr testIP;
		IPAddr originalIP;
		testIP = IPAddr.getAddress(suffix1, maskLengthIP4);
		originalIP = IPAddr.getAddress(ipAddress, maskLengthIP4);

		if (testIP.getMaskedIPAddress().equals(originalIP.getMaskedIPAddress())) {
			return true;
		} else {
			return false;
		}

	}

	/**
	 * Run the checkcommand for the PTR prefix
	 * 
	 * @param domainList
	 *            The domains
	 * @param checkDomain
	 *            The domain to check
	 * @param compareAddress
	 *            The IP address to compare to
	 * @return true or false
	 * @throws ErrorException
	 *             if an error result should returned
	 * @throws UnknownException
	 *             if an unknown result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 */
	protected boolean runPTRCommand(ArrayList domainList, String checkDomain,
			String compareAddress) throws ErrorException, NeutralException,
			NoneException {

		String compareDomain;
		IPAddr compareIP;
		ArrayList validatedHosts = new ArrayList();

		if (!suffix1.equals("")) {
			checkDomain = suffix1;
		}

		for (int i = 0; i < domainList.size(); i++) {

			ArrayList aList = DNSProbe.getARecords((String) domainList.get(i),
					maskLengthIP4);
			for (int j = 0; j < aList.size(); j++) {
				compareIP = (IPAddr) aList.get(j);
				if (compareIP.toString().equals(compareAddress)) {
					validatedHosts.add(domainList.get(i));
				}
			}
		}

		for (int j = 0; j < validatedHosts.size(); j++) {
			compareDomain = (String) validatedHosts.get(j);
			if (compareDomain.equals(checkDomain)
					|| compareDomain.endsWith("." + checkDomain)) {
				return true;
			}
		}

		return false;

	}

	/**
	 * Run the exists Command
	 * 
	 * @return true or false
	 * @throws NeutralException
	 *             if an neutral result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 */
	protected boolean runExistsCommand() throws NeutralException, NoneException {
		ArrayList aRecords;
		try {
			aRecords = DNSProbe.getARecords(suffix1, maskLengthIP4);
		} catch (Exception e) {
			return false;
		}
		if (aRecords.size() > 0) {
			return true;
		}
		return false;

	}

	/**
	 * Run the exists Command
	 * 
	 * @return true or false
	 * @throws NeutralException
	 *             if an neutral result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 * @throws UnknownException
	 *             if an unknown result should returned
	 * @throws ErrorException
	 *             if an error result should returned
	 * @throws IncludeException
	 */

	protected String runIncludeCommand() throws NeutralException,
			ErrorException, UnknownException, IncludeException {

		SPF1Record spf = null;
		if (spfData.getDepth() == 20) {
			throw new IncludeException("loop encountered");
		}

		spfData.setDepth(spfData.getDepth() + 1);
		String redirectDomain = suffix1;

		if (redirectDomain.equals("")) {
			throw new IncludeException(
					"include mechanism not given an argument");
		}
		spfData.setCurrentDomain(redirectDomain);
		try {
			spf = new SPF1Record(DNSProbe.getSpfRecord(redirectDomain,
					spfData.spfVersion), spfData);
		} catch (NoneException e) {
		}
		if (spf == null) {
			throw new IncludeException("Missing SPF record at: "
					+ redirectDomain);
		}
		return spf.runCheck();

	}

	/**
	 * Run the redirect command
	 * 
	 * @return the result if the redirect command
	 * @throws NeutralException
	 *             if an neutral result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 * @throws UnknownException
	 *             if an unknown result should returned
	 * @throws ErrorException
	 *             if an error result should returned
	 */

	protected String runRedirectCommand() throws NeutralException,
			NoneException, ErrorException, UnknownException {

		if (spfData.getDepth() == 20) {
			throw new NeutralException("Recurse depth exceeded");
		}
		spfData.setDepth(spfData.getDepth() + 1);
		String redirectDomain = macroExpandDomain(suffix1);

		SPF1Record spf = new SPF1Record(DNSProbe.getSpfRecord(redirectDomain,
				spfData.spfVersion), spfData);
		spfData.setCurrentDomain(redirectDomain);
		if (spf == null) {
			throw new NeutralException("No spf record");
		}
		return spf.runCheck();
	}

	/**
	 * Run the exp command
	 * 
	 * @return explanation which us contained in the SPF-Record
	 * @throws NeutralException
	 *             if an neutral result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 * @throws ErrorException
	 *             if an error result should returned
	 */
	protected String runExpCommand() throws ErrorException, NoneException,
			NeutralException {

		String txtRecord = macroExpandDomain(suffix1);
		String explanation = DNSProbe.getTxtCatType(txtRecord);
		return new MacroExpand(spfData).expandExplanation(explanation);
	}

	/**
	 * Check if the given ipaddress array contains the provided ip.
	 * 
	 * @param checkAddress
	 *            The ip wich should be contained in the given ArrayList
	 * @param addressList
	 *            The ip ArrayList.
	 * @return true or false
	 */
	private boolean checkAddressList(IPAddr checkAddress, ArrayList addressList) {

		IPAddr aValue = null;
		for (int i = 0; i < addressList.size(); i++) {

			aValue = (IPAddr) addressList.get(i);

			if (checkAddress.getMaskedIPAddress().equals(
					aValue.getMaskedIPAddress())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if its a valid SPF1Command
	 * 
	 * @return true or false
	 * @throws NeutralException
	 *             if an neutral result should returned
	 */

	// TODO: also make records without checkSuffixCommand to work
	private boolean isSPF1Command() throws UnknownException,NeutralException {

		boolean result = false;
		if (checkSuffixCommand("a")) {
			suffix1 = macroExpandDomain(suffix1);
			result = true;
		} else if (checkSuffixCommand("mx")) {

			suffix1 = macroExpandDomain(suffix1);
			result = true;
		} else if (checkSuffixCommand("ip4")) {
			result = true;
		} else if (checkSuffixCommand("ip6")) {
			result = true;
		} else if (checkCommand("all")) {
			result = true;
		} else if (checkCommand("ptr")) {
			suffix1 = macroExpandDomain(suffix1);
			result = true;
		} else if (checkCommand("include")) {
			suffix1 = macroExpandDomain(suffix1);
			result = true;
		} else if (checkCommand("exists")) {
			suffix1 = macroExpandDomain(suffix1);
			result = true;
		} else if (!result) {

			result = checkUnknownMechanism();
			if (result) {

				// throw new UnknownException("Unknown mechanism " + command);
			}
		}
		return result;
	}

	/**
	 * Check if the mechanism is unknown
	 * 
	 * @return true or false
	 */
	private boolean checkUnknownMechanism() {

		String[] temp;
		int firstColon = command.indexOf(":");
		int firstEquals = command.indexOf("=");

		if (firstColon > -1 && firstEquals == -1) {
			temp = command.split(":");
			command = temp[0];
			if (temp.length > 1) {
				suffix1 = temp[1];
			}

			return true;
		} else if (firstColon > -1 && firstEquals > -1
				&& firstColon < firstEquals) {
			temp = command.split(":");
			command = temp[0];
			suffix1 = temp[1];

			return true;
		} else if (firstEquals == -1) {

			return true;
		}
		return false;
	}

	/**
	 * Check if the provided String is a command
	 * 
	 * @param compare
	 *            The string which should checked
	 * @return true or false
	 */
	private boolean checkCommand(String compare) {

		if (command.toLowerCase().equals(compare)
				|| (command.toLowerCase().startsWith(compare + ":"))) {
			String[] temp = command.split(":");
			command = temp[0].trim();
			if (temp.length == 2) {
				suffix1 = temp[1].toLowerCase().trim();
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Check if the provided String is a suffixCommand
	 * 
	 * @param compare
	 *            The String to check
	 * @return true or false
	 * @throws NeutralException
	 */
	private boolean checkSuffixCommand(String compare) throws UnknownException,NeutralException {

		if (compare.equals(command.toLowerCase())
				|| (command.toLowerCase().startsWith(compare + ":"))
				|| (command.toLowerCase().startsWith(compare + "/"))) {

			if ((command.toLowerCase().startsWith(compare + ":"))) {
				splitMasks(command.substring(compare.length() + 1), true);
				command = command.substring(0, compare.length());
				return true;
			}
			if ((command.toLowerCase().startsWith(compare + "/"))) {
				splitMasks(command.substring(compare.length()), false);
				command = command.substring(0, compare.length());
				return true;
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Split ip and netmask
	 * 
	 * @param original
	 * @throws WarningException
	 */

	public void splitMasks(String original, boolean domainSpec)
			throws UnknownException,NeutralException {

		StringBuffer working = new StringBuffer();
		StringBuffer temp = new StringBuffer();

		working.append(original);
		String reversed = working.reverse().toString();

		int ip6Position = reversed.indexOf("//");
		if (ip6Position > 0) {
			String tempDomain = reversed.substring(ip6Position + 2, reversed
					.length());
			temp.setLength(0);
			temp.append(reversed.substring(0, ip6Position));

			maskLengthIP6 = Integer.parseInt(temp.reverse().toString());
			reversed = tempDomain;
		}

		int ip4Position = reversed.indexOf("/");
		if (ip4Position > 0) {
			String tempDomain = reversed.substring(ip4Position + 1, reversed
					.length());
			temp.setLength(0);
			temp.append(reversed.substring(0, ip4Position));

			try {
				maskLengthIP4 = Integer.parseInt(temp.reverse().toString());
			} catch (NumberFormatException e) {
				if (domainSpec == true) {
					if (SPF1Utils.checkFQDN(temp.reverse().toString())) {

					} else {

						throw new UnknownException(
								"Warning: Hostname has a missing or invalid TLD");
					}

				} else {
					// throw new NeutralException("Warning: Hostname has a
					// missing or invalid TLD");
					throw new NeutralException("Invalid CIDR length near \""
							+ original + "\" in \"" + command + "\"");

				}
			}
			reversed = tempDomain;
		}

		working.setLength(0);
		working.append(reversed);
		// set domain name
		suffix1 = working.reverse().toString().trim();

	}

	// TODO: Write javadoc
	private String macroExpandDomain(String data) throws NeutralException {
		return new MacroExpand(spfData).expandDomain(data);
	}

}