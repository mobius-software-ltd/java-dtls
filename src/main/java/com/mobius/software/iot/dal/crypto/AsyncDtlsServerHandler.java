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

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.TlsFatalAlert;

import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.MessageToMessageDecoder;

@io.netty.channel.ChannelHandler.Sharable
public class AsyncDtlsServerHandler extends MessageToMessageDecoder<DatagramPacket>
{
	private AsyncDtlsServerContextMap map;
	private KeyStore keystore;
	private String keystorePassword;
	private ConcurrentHashMap<SocketAddress, Channel> channels;
	private DtlsStateHandler handler;
	
	public AsyncDtlsServerHandler(KeyStore keystore,String keystorePassword,AsyncDtlsServerContextMap map,ConcurrentHashMap<SocketAddress, Channel> channels,DtlsStateHandler handler)
	{
		this.map=map;
		this.keystore=keystore;
		this.keystorePassword=keystorePassword;
		this.channels=channels;
		this.handler=handler;
	}
	
	public Certificate getCertificate(InetSocketAddress address)
	{
		AsyncDtlsServerProtocol server=map.getExistingDtlsServerProtocol(address);
		if(server!=null)
			return server.getClientCertificate();
		
		return null;		
	}
	
	@Override
	protected void decode(ChannelHandlerContext ctx, DatagramPacket packet,List<Object> out) throws Exception 
	{
		Channel channel = ctx.channel();
		channels.put(packet.sender(), channel);
		
		AsyncDtlsServerProtocol server=map.getDtlsServerProtocol(keystore, keystorePassword, ctx.channel(),packet.sender());
		try
		{
			List<ByteBuf> parsedPackets=server.receivePacket(packet.content());
			if(parsedPackets.size()>0)
			{
				if(parsedPackets.size()>0)
				{
					for(ByteBuf currBuffer:parsedPackets)
						out.add(new DatagramPacket(currBuffer, packet.recipient(), packet.sender()));					
				}
			}
		}
		catch(TlsFatalAlert ex)
		{
			ex.printStackTrace();
			try
			{
				server.sendAlert(AlertLevel.fatal, ex.getAlertDescription(), ex.getMessage(),ex.getCause());
			}
			catch(Exception ex1)
			{				
			}
			
			if(handler!=null)
				handler.errorOccured(packet.sender(), channel);			
		}
		catch(Exception ex)
		{
			ex.printStackTrace();
			try
			{
				server.sendAlert(AlertLevel.fatal, AlertDescription.decode_error, ex.getMessage(),ex.getCause());
			}
			catch(Exception ex1)
			{
			}
			
			map.remove(packet.sender());
			channels.remove(packet.sender(), channel);
		}
	}
	
	@Override
	public void channelInactive(ChannelHandlerContext ctx) throws Exception
	{
		
	}
}