package com.mobius.software.iot.dal.test.dtls;

import io.netty.buffer.ByteBuf;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import com.mobius.software.iot.dal.crypto.HandshakeHandler;
import com.mobius.software.iot.dal.crypto.MessageType;

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

public class TestHandshakeHandler implements HandshakeHandler 
{
	private ConcurrentHashMap<MessageType, AtomicInteger> messagesReceived=new ConcurrentHashMap<MessageType, AtomicInteger>();
	
	public TestHandshakeHandler()
	{
		for(MessageType type:MessageType.values())
			messagesReceived.put(type, new AtomicInteger(0));
	}
	
	@Override
	public void handleHandshake(MessageType messageType, ByteBuf data) throws IOException 
	{
		messagesReceived.get(messageType).incrementAndGet();
	}
	
	public Integer getCount(MessageType type)
	{
		return messagesReceived.get(type).get();
	}

	@Override
	public void postProcessHandshake(MessageType messageType, ByteBuf data) throws IOException 
	{		
	}
}