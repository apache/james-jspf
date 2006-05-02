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

package org.apache.james.spf.util;

import java.util.ArrayList;

import org.apache.james.spf.PermErrorException;

/**
 * @author MimeCast
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class IPAddr {

    // Default IP4

    private static final int MASK8 = 255;

    private static final int MASK16 = 65535;

    private int[] address = new int[4];

    private int[] mask = new int[4];

    private int maskLength = 32;

    private int ipLength = 4;

    private int ipRun = 4;

    private String ipJoiner = ".";

    // Allow factory creates only
    private IPAddr() {

    }

    /**
     * Get ArrayList with ipAddresses for the given host and netmask
     * 
     * @param host
     *            The hostname or ip we want to retrieve the ipaddresses for
     * @param mask
     *            The netmask
     * @return ipAddresses
     * @throws PermErrorException
     *             on error
     */
    public static ArrayList getAddresses(String host, int mask)
            throws PermErrorException {

        ArrayList addressList = new ArrayList();

        if (host != null) {
            addressList.add(getAddress(host, mask));
        }

        return addressList;
    }

    /**
     * Get ipAddress for the given byte array and netmask
     * 
     * @param netAddress
     *            The ipAddress given as byte Array
     * @param maskLength
     *            The netmask
     * @return IpAddress
     * @throws PermErrorException
     *             on error
     */
    public static IPAddr getAddress(byte[] netAddress, int maskLength)
            throws PermErrorException {
        IPAddr returnAddress = new IPAddr();
        returnAddress.byteToInternal(netAddress);
        returnAddress.setMask(maskLength);
        return returnAddress;
    }

    /**
     * 
     * @see #getAddress(byte[], int)
     */
    public static IPAddr getAddress(byte[] netAddress)
            throws PermErrorException {
        IPAddr returnAddress = new IPAddr();
        returnAddress.byteToInternal(netAddress);
        returnAddress.setMask(returnAddress.maskLength);
        return returnAddress;
    }

    /**
     * Get ipAddress for the given String and netmask
     * 
     * @param netAddress
     *            The ipAddress given as String
     * @param maskLength
     *            The netmask
     * @return IpAddress
     * @throws PermErrorException
     *             on error
     */
    public static IPAddr getAddress(String netAddress, int maskLength)
            throws PermErrorException {
        IPAddr returnAddress = new IPAddr();
        returnAddress.stringToInternal(netAddress);
        returnAddress.setMask(maskLength);
        return returnAddress;
    }

    /**
     * 
     * @see #getAddress(String, int)
     */
    public static IPAddr getAddress(String netAddress)
            throws PermErrorException {
        IPAddr returnAddress = new IPAddr();
        returnAddress.stringToInternal(netAddress);
        returnAddress.setMask(returnAddress.maskLength);
        return returnAddress;
    }

    /**
     * Check if a the Object is instance of this class
     * 
     * @param data
     *            The object to check
     * @return true or false
     */
    public static boolean isIPAddr(Object data) {
        if (data instanceof String) {
            try {
                getAddress((String) data);
                return true;
            } catch (Exception e) {
                return false;
            }
        } else if (data instanceof byte[]) {
            try {
                getAddress((byte[]) data);
                return true;
            } catch (Exception e) {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Set default values for ipv6
     * 
     */
    private void setIP6Defaults() {
        ipLength = 16;
        ipJoiner = ":";
        address = new int[8];
        mask = new int[8];
        ipRun = 8;
    }

    /**
     * create series of 16 bit masks for each ip block
     * 
     * @param maskLength
     *            The netmask
     */
    public void setMask(int maskLength) {
        int startMask;
        int shift;
        int maskSize;

        this.maskLength = maskLength;
        if (ipLength == 4) {
            if (!((maskLength > -1) && (maskLength < 33))) {
                maskLength = 32;
            }
            maskSize = 8;
            startMask = (maskLength - 1) / maskSize;
        } else {
            if (!((maskLength > -1) && (maskLength < 129))) {
                maskLength = 128;
            }
            maskSize = 16;
            startMask = (maskLength - 1) / maskSize;
        }

        for (int i = 0; i < ipRun; i++) {
            // full mask
            if (i < startMask) {
                mask[i] = MASK16;
                // variable mask
            } else if (i == startMask) {
                shift = ((i + 1) * maskSize) - maskLength;
                mask[i] = (MASK16 << shift) & MASK16;
                // no mask
            } else {
                mask[i] = 0;
            }
        }
    }

    /**
     * Convert ipAddress given as byte Array to ipAddress
     * 
     * @param netAddress
     *            The ipAddress given as byte Array
     * 
     * @throws PermErrorException
     *             on error
     */
    private void byteToInternal(byte[] netAddress) throws PermErrorException {
        if (netAddress.length == 16) {
            // IP6 defaults
            setIP6Defaults();
            // set internal address
            for (int i = 0; i < ipRun; i++) {
                // TODO Endianess????
                address[i] = get16Bit(unsigned(netAddress[i * 2]),
                        unsigned(netAddress[i + 1]));
            }
        } else if (netAddress.length == 4) {
            // set internal address
            for (int i = 0; i < ipRun; i++) {
                address[i] = unsigned(netAddress[i]);
            }
        } else {
            throw new PermErrorException("Not a valid IP byte address");
        }
    }

    /**
     * Strip the last char of a string when it ends with a dot
     * 
     * @param data
     *            The String where the dot should removed
     * @return modified String
     */
    public static String stripDot(String data) {

        data = data.trim();

        if (data.endsWith(".")) {
            return data.substring(0, data.length() - 1);
        } else {
            return data;
        }

    }

    /**
     * Convert ipAddress to a byte Array which represent the ipAddress
     * 
     * @param netAddress
     *            The ipAddress we should convert
     * @throws PermErrorException
     *             on error
     */
    private void stringToInternal(String netAddress) throws PermErrorException {
        netAddress = stripDot(netAddress);
        
        byte[] bytes = Inet6Util.createByteArrayFromIPAddressString(netAddress);
        
        if (bytes.length == 4) {
            for (int i = 0; i < bytes.length; i++) {
                address[i] = bytes[i];
            }
        } else if (bytes.length == 16){
            setIP6Defaults();
            for (int i = 0; i < bytes.length / 2; i++) {
                address[i] = bytes[i*2]*256+bytes[i*2+1];
            }
        } else {
            throw new PermErrorException("Not a valid address: "+netAddress);
        }
    }

    private int get16Bit(int msb, int lsb) {
        return (msb * 256) + lsb;
    }

    private String getHex(long data) {
        StringBuffer fullHex = new StringBuffer();
        fullHex.append("0000" + Long.toHexString(data).toUpperCase());
        fullHex = fullHex.delete(0, fullHex.length() - 4);
        return fullHex.toString();
    }

    /**
     * @see #getInAddress(String)
     */
    public String getIPAddress() {
        return getIPAddress(address);
    }

    /**
     * Get ip Address from given int Array
     * 
     * @param addressData
     *            The int Array
     * @return ipAddress
     */
    private String getIPAddress(int[] addressData) {
        StringBuffer createAddress = new StringBuffer();
        int[] workingAddress;

        // convert internal address to 8 bit
        if (ipLength == 4) {
            workingAddress = get8BitAddress(addressData);
            // create IP string
            createAddress.append(workingAddress[0]);
            for (int i = 1; i < ipRun; i++) {
                createAddress.append(ipJoiner + workingAddress[i]);
            }
            // leave internal address as 16 bit
        } else {
            workingAddress = addressData;
            // create IP string
            createAddress.append(getHex(workingAddress[0]));
            for (int i = 1; i < ipRun; i++) {
                createAddress.append(ipJoiner + getHex(workingAddress[i]));
            }
        }

        return createAddress.toString();
    }

    public String getMaskedIPAddress() {
        return getIPAddress(maskedAddress(address, mask));
    }

    public String getMaskAddress() {
        if (ipLength == 4) {
            return getIPAddress(get8BitAddress(mask));
        } else {
            return getIPAddress(mask);
        }
    }

    // TODO
    // public String getNibbleFormat(){
    // //ie : IP6 = 5f05:2000:80ad:5800::1 therefore nibble format =
    // 5.f.0.5.0.0.0.0.2.0.0.0.8.0.a.d.5.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1
    // // IP4 = 192.0.0.1 therefore nibble format = 197.0.0.1
    // return nibbledAddress;
    // }

    // TODO needs to changed to handle IP6 nibble format
    /**
     * Get reverse ipAddress
     * 
     * @return reverse ipAddress
     */
    public String getReverseIP() {
        return getIPAddress(reverseIP(address));
    }

    /**
     * Converts 16 bit representation to 8 bit for IP4
     * 
     * @param addressData
     *            The given int Array
     * @return converted String
     */
    private int[] get8BitAddress(int[] addressData) {
        int[] convertAddress = new int[4];
        for (int i = 0; i < ipRun; i++) {
            convertAddress[i] = addressData[i] & MASK8;
        }
        return convertAddress;
    }

    /**
     * Create a masked address given an address and mask
     * 
     * @param addressData
     *            The int Array represent the ipAddress
     * @param maskData
     *            The int array represent the mask
     * @return maskedAddress
     */
    private int[] maskedAddress(int[] addressData, int[] maskData) {
        int[] maskedAddress = new int[ipLength];

        for (int i = 0; i < ipRun; i++) {
            maskedAddress[i] = addressData[i] & maskData[i];
        }
        return maskedAddress;
    }

    /**
     * Reverses internal address
     * 
     * @param addressData
     *            The int array represent the ipAddress
     * @return reverseIP
     */
    private int[] reverseIP(int[] addressData) {
        int[] reverseIP = new int[ipLength];
        int temp;
        for (int i = 0; i < ipRun; i++) {
            temp = addressData[i];
            reverseIP[i] = addressData[(ipRun - 1) - i];
            reverseIP[(ipRun - 1) - i] = temp;
        }
        return reverseIP;
    }

    /**
     * Get mask length
     * 
     * @return maskLength
     */
    public int getMaskLength() {
        return maskLength;
    }

    public String toString() {
        return getIPAddress();
    }

    private int unsigned(byte data) {
        return data >= 0 ? data : 256 + data;
    }

    /**
     * This method return the InAddress for the given ip.
     * 
     * @param ipAddress -
     *            ipAddress that should be processed
     * @return the inAddress (in-addr or ip6)
     * @throws PermErrorException
     *             if the ipAddress is not valid (rfc conform)
     */
    public static String getInAddress(String ipAddress)
            throws PermErrorException {
        if (ipAddress == null) {
            throw new PermErrorException(
                    "IP is not a valid ipv4 or ipv6 address");
        } else if (Inet6Util.isValidIPV4Address(ipAddress)) {
            return "in-addr";
        } else if (Inet6Util.isValidIP6Address(ipAddress)) {
            return "ipv6";
        } else {
            throw new PermErrorException(
                    "IP is not a valid ipv4 or ipv6 address");
        }
    }

    /**
     * Check if the given IP is valid. Works with ipv4 and ip6
     * 
     * @param ip
     *            The ipaddress to check
     * @return true or false
     */
    public static boolean isValidIP(String ip) {
        return ip != null
                && (Inet6Util.isValidIPV4Address(ip) || Inet6Util
                        .isValidIP6Address(ip));
    }
}