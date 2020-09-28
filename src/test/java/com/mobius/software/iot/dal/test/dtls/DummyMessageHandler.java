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

import org.apache.log4j.Logger;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;

public class DummyMessageHandler extends SimpleChannelInboundHandler<DatagramPacket>
{
	private final static Logger logger = Logger.getLogger(DummyMessageHandler.class);
    
	private MessageHandlerInterface handlerInterface;
	
	public DummyMessageHandler(MessageHandlerInterface handlerInterface)
	{
		this.handlerInterface = handlerInterface;
	}
	
	@Override
	protected void channelRead0(ChannelHandlerContext ctx, DatagramPacket msg) throws Exception 
	{
		byte[] messageContent=new byte[msg.content().readableBytes()];
		msg.content().readBytes(messageContent);
		logger.info("Message Received:" + new String(messageContent));
		this.handlerInterface.messageReceived(new String(messageContent));
	}
}