package com.mobius.software.iot.dal.test.dtls;

/**
 * Mobius Software LTD
 * Copyright 2018, Mobius Software LTD
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

public class IPAddressCompare {

	public static boolean isInRangeV4(byte[] network, byte[] subnet,
			byte[] ipAddress) {
		if (network.length != 4 || subnet.length != 4 || ipAddress.length != 4)
			return false;

		return compareByteValues(network, subnet, ipAddress);
	}

	public static boolean isInRangeV6(byte[] network, byte[] subnet,
			byte[] ipAddress) {
		if (network.length != 16 || subnet.length != 16
				|| ipAddress.length != 16)
			return false;

		return compareByteValues(network, subnet, ipAddress);
	}

	private static boolean compareByteValues(byte[] network, byte[] subnet,
			byte[] ipAddress) {
		for (int i = 0; i < network.length; i++)
			if ((network[i] & subnet[i]) != (ipAddress[i] & subnet[i]))
				return false;

		return true;
	}

	public static IPAddressType getAddressType(String ipAddress) {
		if (textToNumericFormatV4(ipAddress) != null)
			return IPAddressType.IPV4;

		if (textToNumericFormatV6(ipAddress) != null)
			return IPAddressType.IPV6;

		return IPAddressType.INVALID;
	}

	public static byte[] addressToByteArrayV4(String ipAddress) {
		return textToNumericFormatV4(ipAddress);
	}

	public static byte[] addressToByteArrayV6(String ipAddress) {
		return textToNumericFormatV6(ipAddress);
	}

	public static byte[] textToNumericFormatV4(String src) {
		if (src.length() == 0) {
			return null;
		}

		byte[] res = new byte[4];
		String[] s = src.split("\\.", -1);
		long val;
		try {
			switch (s.length) {
			case 1:
				val = Long.parseLong(s[0]);
				if (val < 0 || val > 0xffffffffL)
					return null;
				res[0] = (byte) ((val >> 24) & 0xff);
				res[1] = (byte) (((val & 0xffffff) >> 16) & 0xff);
				res[2] = (byte) (((val & 0xffff) >> 8) & 0xff);
				res[3] = (byte) (val & 0xff);
				break;
			case 2:
				val = Integer.parseInt(s[0]);
				if (val < 0 || val > 0xff)
					return null;
				res[0] = (byte) (val & 0xff);
				val = Integer.parseInt(s[1]);
				if (val < 0 || val > 0xffffff)
					return null;
				res[1] = (byte) ((val >> 16) & 0xff);
				res[2] = (byte) (((val & 0xffff) >> 8) & 0xff);
				res[3] = (byte) (val & 0xff);
				break;
			case 3:
				for (int i = 0; i < 2; i++) {
					val = Integer.parseInt(s[i]);
					if (val < 0 || val > 0xff)
						return null;
					res[i] = (byte) (val & 0xff);
				}
				val = Integer.parseInt(s[2]);
				if (val < 0 || val > 0xffff)
					return null;
				res[2] = (byte) ((val >> 8) & 0xff);
				res[3] = (byte) (val & 0xff);
				break;
			case 4:
				for (int i = 0; i < 4; i++) {
					val = Integer.parseInt(s[i]);
					if (val < 0 || val > 0xff)
						return null;
					res[i] = (byte) (val & 0xff);
				}
				break;
			default:
				return null;
			}
		} catch (NumberFormatException e) {
			return null;
		}

		return res;
	}

	public static byte[] textToNumericFormatV6(String src) {
		if (src.length() < 2)
			return null;

		int colonp;
		char ch;
		boolean saw_xdigit;
		int val;
		char[] srcb = src.toCharArray();
		byte[] dst = new byte[16];

		int srcb_length = srcb.length;
		int pc = src.indexOf("%");
		if (pc == srcb_length - 1)
			return null;

		if (pc != -1)
			srcb_length = pc;

		colonp = -1;
		int i = 0, j = 0;

		if (srcb[i] == ':' && srcb[++i] != ':')
			return null;

		int curtok = i;
		saw_xdigit = false;
		val = 0;
		while (i < srcb_length) {
			ch = srcb[i++];
			int chval = Character.digit(ch, 16);
			if (chval != -1) {
				val <<= 4;
				val |= chval;
				if (val > 0xffff)
					return null;

				saw_xdigit = true;
				continue;
			}

			if (ch == ':') {
				curtok = i;
				if (!saw_xdigit) {
					if (colonp != -1)
						return null;

					colonp = j;
					continue;
				} else if (i == srcb_length)
					return null;

				if (j + 16 > 16)
					return null;

				dst[j++] = (byte) ((val >> 8) & 0xff);
				dst[j++] = (byte) (val & 0xff);
				saw_xdigit = false;
				val = 0;
				continue;
			}

			if (ch == '.' && ((j + 4) <= 16)) {
				String ia4 = src.substring(curtok, srcb_length);
				int dot_count = 0, index = 0;

				while ((index = ia4.indexOf('.', index)) != -1) {
					dot_count++;
					index++;
				}

				if (dot_count != 3)
					return null;

				byte[] v4addr = textToNumericFormatV4(ia4);
				if (v4addr == null)
					return null;

				for (int k = 0; k < 4; k++)
					dst[j++] = v4addr[k];

				saw_xdigit = false;
				break;
			}

			return null;
		}

		if (saw_xdigit) {
			if (j + 16 > 16)
				return null;

			dst[j++] = (byte) ((val >> 8) & 0xff);
			dst[j++] = (byte) (val & 0xff);
		}

		if (colonp != -1) {
			int n = j - colonp;

			if (j == 16)
				return null;

			for (i = 1; i <= n; i++) {
				dst[16 - i] = dst[colonp + n - i];
				dst[colonp + n - i] = 0;
			}

			j = 16;
		}
		if (j != 16)
			return null;

		byte[] newdst = convertFromIPv4MappedAddress(dst);
		if (newdst != null)
			return newdst;
		else
			return dst;
	}

	public static byte[] convertFromIPv4MappedAddress(byte[] addr) {
		if (isIPv4MappedAddress(addr)) {
			byte[] newAddr = new byte[4];
			System.arraycopy(addr, 12, newAddr, 0, 4);
			return newAddr;
		}
		return null;
	}

	private static boolean isIPv4MappedAddress(byte[] addr) {
		if (addr.length < 16)
			return false;

		if ((addr[0] == 0x00) && (addr[1] == 0x00) && (addr[2] == 0x00)
				&& (addr[3] == 0x00) && (addr[4] == 0x00) && (addr[5] == 0x00)
				&& (addr[6] == 0x00) && (addr[7] == 0x00) && (addr[8] == 0x00)
				&& (addr[9] == 0x00) && (addr[10] == (byte) 0xff)
				&& (addr[11] == (byte) 0xff))

			return true;

		return false;
	}
}