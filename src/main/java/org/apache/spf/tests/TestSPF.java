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

package org.apache.spf.tests;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.spf.SPF;

/**
 * @author maurer
 *
 */
public class TestSPF {

	/**
	 * 
	 * @param inputFile - The file which should be parsed
	 * @param outputFile - The file in which the results will get stored
	 */
	public void runTest(String inputFile, String outputFile) {
		FileOutputStream outFile;
		FileInputStream testFile;
		try {
			outFile = new FileOutputStream(outputFile);
			testFile = new FileInputStream(inputFile);
			InputStreamReader isReader = new InputStreamReader(testFile);
			BufferedReader brData = new BufferedReader(isReader);

			String line = null;
			String command = null;
			String resultNew = null;

			try {
				while ((line = brData.readLine()) != null) {
					String newline = "\n";

					//System.out.println(line);
					if (line.startsWith("spfquery -ip=")) {
						command = line;
						String[] values = line.substring(9).split(" ");

						// Only run checks which we support!
						if (values.length == 3) {

							String ip = values[0].substring(4).trim();
							String sender = values[1].substring(8).trim();
							String helo = values[2].substring(6).trim();
							String startComment = "----------------------------------";
							String ipComment = "ip:     " + ip;
							String senderComment = "sender:	" + sender;
							String heloComment = "helo:	" + helo;
							System.out.println(startComment);
							System.out.println(ipComment);
							System.out.println(senderComment);
							System.out.println(heloComment);

							outFile.write(startComment.getBytes());
							outFile.write(newline.getBytes());
							outFile.write(ipComment.getBytes());
							outFile.write(newline.getBytes());
							outFile.write(senderComment.getBytes());
							outFile.write(newline.getBytes());
							outFile.write(heloComment.getBytes());
							outFile.write(newline.getBytes());

							SPF spf = new SPF();
							resultNew = spf.checkSPF(ip, sender, helo);
						}
					} else if (line.startsWith("result ") && resultNew != null) {
						String result = line.substring(21);

						if (resultNew.equals(result)) {
							String testResultComment = "TestResult: PASS";
							System.out.println(testResultComment);
							outFile.write(testResultComment.getBytes());
							outFile.write(newline.getBytes());

						} else {
							String testResultComment = "TestResult: ERROR";
							String resultComment = "Result:	   " + result;
							String resultNewComment = "ResultNew: " + resultNew;

							System.out.println(testResultComment);
							System.out.println(resultComment);
							System.out.println(resultNewComment);

							outFile.write(testResultComment.getBytes());
							outFile.write(newline.getBytes());
							outFile.write(resultComment.getBytes());
							outFile.write(newline.getBytes());
							outFile.write(resultNewComment.getBytes());
							outFile.write(newline.getBytes());
							outFile.write(command.getBytes());
							outFile.write(newline.getBytes());
						}
						String endComment = "----------------------------------";
						System.out.println(endComment);
						outFile.write(endComment.getBytes());
						outFile.write(newline.getBytes());
						resultNew = null;
						command = null;
					}
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		String outputFile = "/home/maurer/result.txt";
		String inputFile = "/home/maurer/test.txt";

		TestSPF test = new TestSPF();

		//run the tests!
		test.runTest(inputFile, outputFile);
	}

}
