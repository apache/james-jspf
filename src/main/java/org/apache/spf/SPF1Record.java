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

import java.util.ArrayList;

/**
 * This class represent the SPF-Record
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

public class SPF1Record {

	private final String SPF_VERSION1 = "v=spf1";

	private ArrayList spfMechanisms = new ArrayList();

	private ArrayList spfModifiers = new ArrayList();

	private SPF1Data spfData;
	private String rawRecord = null;

	protected SPF1Record(String record, SPF1Data spfData) throws NoneException,
			NeutralException {

		this.spfData = spfData;

		// Check if the submitted record starts with a supported spf version

		if (record.startsWith(SPF_VERSION1 + " ")) {
			String mainSpfRecord = extractMainSpfRecord(record);
			
			rawRecord = mainSpfRecord;
			
			parseCommands(mainSpfRecord);
		} else {
			String[] recordParts = record.split(" ");
			String spfRecord = recordParts[0];
			if (recordParts[0].startsWith(SPF_VERSION1)) {
				//SPF-Version was given but the space was missed
				throw new NoneException(
						"Could not find a valid SPF record near \""
								+ SPF_VERSION1 + "\" in \"" + spfRecord + "\"");
			} else if (recordParts[0].startsWith("v=")) {
				//SPF-Version wrong
				throw new NoneException(
						"Could not find a valid SPF record near \""
								+ spfRecord.charAt(0) + "\" in \"" + spfRecord
								+ "\"");
			} else {
				// No valid record at all
				throw new NoneException(
						"Could not find a valid SPF record in \"" + record
								+ "\"");
			}

		}

	}

	/**
	 * Extract main SPF-Record from raw SPF Record
	 * 
	 * @param record
	 *            The raw SPF Record
	 * @return main SPF-Record
	 */
	private String extractMainSpfRecord(String record) {
		String mainSpfRecord = record;


		mainSpfRecord.substring(SPF_VERSION1.length() + 1);
		return mainSpfRecord;

	}

	/**
	 * Parse the given String for Commands
	 * 
	 * @param commandText
	 *            The command text to parse
	 * @throws NeutralException
	 */
	private void parseCommands(String commandText) throws NeutralException {

		SPF1Command processCommand;
		String currentSplit = "";
		String[] temp = commandText.split(" ");
		for (int i = 0; i < temp.length; i++) {
			currentSplit = temp[i].trim();
			if (!currentSplit.equals("")) {
				System.out.println("current: " + currentSplit);
				
				processCommand = new SPF1Command(currentSplit, spfData);
				System.out.println("PRE: " + processCommand.toString());
				if (processCommand.isMechanism()) {
					spfMechanisms.add(processCommand);
				} else {
					spfModifiers.add(processCommand);
				}
			}
		}
	}

	/**
	 * Get a list of SPF-Commands
	 * 
	 * @return SPF-Commands
	 */
	protected ArrayList getSPFCommands() {
		return spfMechanisms;
	}

	/**
	 * Run SPF-Check with data from SPF1Data
	 * 
	 * @return result
	 * @throws NeutralException
	 *             if an neutral result should returned
	 * @throws NoneException
	 *             if an none result should returned
	 * @throws UnknownException
	 *             if an unknown result should returned
	 * @throws ErrorException
	 *             if an error result should returned
	 */
	protected String runCheck() throws NeutralException, NoneException,
			ErrorException, UnknownException {

		String result = SPF1Utils.NEUTRAL;
		SPF1Command runCommand;

		for (int i = 0; i < spfMechanisms.size(); i++) {

			runCommand = (SPF1Command) spfMechanisms.get(i);

			IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress());
			if (runCommand.isCommand("a")) {
				if (runCommand.runACommand(checkAddress, spfData
						.getCurrentDomain())) {
					return runCommand.getPrefix();
				}
			} else if (runCommand.isCommand("mx")) {
				if (runCommand.runMXCommand(checkAddress, spfData
						.getCurrentDomain())) {
					return runCommand.getPrefix();
				}
			} else if (runCommand.isCommand("all")) {
				// As soon as All is reached, stop processing
				return runCommand.getPrefix();
			} else if (runCommand.isCommand("ptr")) {
				if (runCommand.runPTRCommand(DNSProbe.getPTRRecords(spfData
						.getIpAddress()), spfData.getCurrentDomain(), spfData
						.getIpAddress())) {
					return runCommand.getPrefix();
				}
			} else if (runCommand.isCommand("ip4")) {
				if (runCommand.runIPCommand(spfData.getIpAddress())) {
					return runCommand.getPrefix();
				}
			} else if (runCommand.isCommand("ip6")) {
				if (runCommand.runIPCommand(spfData.getIpAddress())) {
					return runCommand.getPrefix();
				}
			} else if (runCommand.isCommand("include")) {
				try {
					if (runCommand.runIncludeCommand().equals(SPF1Utils.PASS)) {
						return SPF1Utils.PASS;
					}
				} catch (Exception e) {
					throw new UnknownException("Unknown include "
							+ e.getMessage());
				}
			} else if (runCommand.isCommand("exists")) {
				if (runCommand.runExistsCommand()) {
					return runCommand.getPrefix();
				}
			} else if (runCommand.isCommand("redirect")) {
				return runCommand.runRedirectCommand();
			} else {


				if (runCommand.isMechanism()) {
					
					spfData.setUnknownCommand(runCommand.getPrefix()
							+ runCommand.getCommand());

					if(rawRecord.contains(":")) {
						String [] chars = rawRecord.split(":");
						
						throw new UnknownException("Unknown mechanism found near \""
								 + runCommand.getCommand() + "\" in \"" + runCommand.getCommand() + ":" + chars[1] + "\"");
						
					} else {

						throw new UnknownException("Unknown mechanism found in \""
							+ runCommand.getCommand() + "\"");
				

				}

				}
			}

		}

		// check for modifiers
		for (int i = 0; i < spfModifiers.size(); i++) {
			System.out.println("mod: " + spfModifiers.get(i));
			runCommand = (SPF1Command) spfModifiers.get(i);
			if (runCommand.isCommand("redirect")) {
				return runCommand.runRedirectCommand();
			}
			if (runCommand.isCommand("default")) {
				if (runCommand.getSuffix().equals("deny") || runCommand.getSuffix().equals("softfail")) {
				//TODO: check for valid default entry 
					return SPF1Utils.nameToResult(runCommand.getSuffix());
				} else {
					throw new UnknownException("Invalid option found in \"default=" +runCommand.getSuffix() + "\"");
				}
			}
		}

		// //check if explanation necessary
		// if(result.equals(SPF.FAIL)){
		// for (int i = 0; i < spfModifiers.size(); i++) {
		// runCommand = (SPFCommand) spfModifiers.get(i);
		// if(runCommand.isCommand("exp")){
		// spfData.explanation = runCommand.runExpCommand(spfData);
		// }
		// }
		// }

		return result;
	}

	/**
	 * Get the explanation of the SPF-Record. If there is none, generate one!
	 * 
	 * @return explanation
	 */
	protected String getExplanation() {

		String result = "";
		SPF1Command searchCommand;

		for (int i = 0; i < spfMechanisms.size(); i++) {
			searchCommand = (SPF1Command) spfMechanisms.get(i);
			if (searchCommand.isCommand("exp")) {
				try {
					result = searchCommand.runExpCommand();
				} catch (Exception e) {
					result = "";
				}
			}
		}
		
		// if the domain has no explanation , generate one!
		if (result == null || result.equals("") ) {
			String explanation = "http://www.openspf.org/why.html?sender=%{S}&ip=%{I}";
			try {
				return new MacroExpand(spfData).expandExplanation(explanation);
			} catch (NeutralException e) {}
		}
		return result;
	}

	public String toString() {

		StringBuffer toText = new StringBuffer();
		for (int i = 0; i < spfMechanisms.size(); i++) {
			if (toText.length() > 0) {
				toText.append("\r\n");
			}
			toText.append(spfMechanisms.get(i));
		}
		return toText.toString();
	}

}