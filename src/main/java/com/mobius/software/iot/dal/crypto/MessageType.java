package com.mobius.software.iot.dal.crypto;

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

import java.util.HashMap;
import java.util.Map;

public enum MessageType
{
	HELLO_REQUEST(0), CLIENT_HELLO(1), SERVER_HELLO(2), HELLO_VERIFY_REQUEST(3), SESSION_TICKET(4), CERTIFICATE(11), SERVER_KEY_EXCHANGE(12), CERTIFICATE_REQUEST(13), SERVER_HELLO_DONE(14), CERTIFICATE_VERIFY(15), CLIENT_KEY_EXCHANGE(16), FINISHED(20), CERTIFICATE_URL(21), CERTIFICATE_STATUS(22),SUPPLEMENTAL_DATA(23);
	
	private static final Map<Integer, MessageType> intToTypeMap = new HashMap<Integer, MessageType>();
	static
	{
		for (MessageType type : MessageType.values())
		{
			intToTypeMap.put(type.value, type);
		}
	}

	public static MessageType fromInt(int i)
	{
		MessageType type = intToTypeMap.get(Integer.valueOf(i));
		return type;
	}

	int value;

	private MessageType(int value)
	{
		this.value = value;
	}

	public int getValue()
	{
		return value;
	}
}
