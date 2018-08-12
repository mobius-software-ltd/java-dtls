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

import java.util.List;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.TlsFatalAlert;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.MessageToMessageDecoder;

public class AsyncDtlsClientHandler extends MessageToMessageDecoder<DatagramPacket>
{
	private AsyncDtlsClientProtocol protocol;
	private DtlsStateHandler handler;
	public AsyncDtlsClientHandler(AsyncDtlsClientProtocol protocol,DtlsStateHandler handler) throws Exception
	{
		this.protocol=protocol;
		this.handler=handler;
	}
	
	@Override
	protected void decode(ChannelHandlerContext ctx, DatagramPacket packet,List<Object> out) throws Exception 
	{
		try
		{
			List<ByteBuf> parsedPackets=protocol.receivePacket(packet.content());
			if(parsedPackets.size()>0)
			{
				for(ByteBuf currBuffer:parsedPackets)
					out.add(new DatagramPacket(currBuffer, packet.recipient()));					
			}
		}
		catch(TlsFatalAlert ex)
		{
			try
			{
				protocol.sendAlert(AlertLevel.fatal, ex.getAlertDescription(), ex.getMessage(),ex.getCause());
			}
			catch(Exception ex1)
			{				
			}
			
			if(handler!=null)
				handler.errorOccured(packet.sender(),ctx.channel());			
		}
		catch(Exception ex)
		{
			System.out.println("ERROR:" + ex.getMessage());
			ex.printStackTrace();
			try
			{
				protocol.sendAlert(AlertLevel.fatal, AlertDescription.decode_error, ex.getMessage(),ex.getCause());
			}
			catch(Exception ex1)
			{				
			}
			
			if(handler!=null)
				handler.errorOccured(packet.sender(),ctx.channel());
		}
	}
}