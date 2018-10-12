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

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioDatagramChannel;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.bouncycastle.crypto.tls.Certificate;

import com.mobius.software.iot.dal.crypto.AsyncDtlsServerContextMap;
import com.mobius.software.iot.dal.crypto.AsyncDtlsServerHandler;
import com.mobius.software.iot.dal.crypto.AsyncDtlsServerProtocol;
import com.mobius.software.iot.dal.crypto.DtlsStateHandler;
import com.mobius.software.iot.dal.crypto.MessageType;

public class DtlsServer implements MessageHandlerInterface,DtlsStateHandler
{
	private final static Logger logger = Logger.getLogger(DtlsServer.class);
    
	private NioEventLoopGroup group;
	private Bootstrap bootstrap;
	private List<Channel> serverChannels = new ArrayList<>();
	protected ConcurrentHashMap<SocketAddress, Channel> channels=new ConcurrentHashMap<SocketAddress,Channel>();
	private String host;
	private int port;
	
	private TestHandshakeHandler handshakeHandler=new TestHandshakeHandler();
	private AsyncDtlsServerContextMap contextMap=new AsyncDtlsServerContextMap(handshakeHandler,this);
	
	private AtomicInteger messagesCount=new AtomicInteger(0);
	private ArrayList<String> messages=new ArrayList<String>();
	
	private KeyStore keystore;
	private String keystorePassword;
	
	public DtlsServer(String host,int port,KeyStore keystore,String keystorePassword)
	{
		this.keystore=keystore;
		this.keystorePassword=keystorePassword;
		this.host=host;
		this.port=port;		
	}
	
	public void initServer()
	{
		group = new NioEventLoopGroup(4);
		bootstrap = new Bootstrap();
		bootstrap.channel(NioDatagramChannel.class);
		bootstrap.group(group);
		bootstrap.option(ChannelOption.SO_SNDBUF, 65536);
		bootstrap.option(ChannelOption.SO_RCVBUF, 65536);
		
		final DtlsServer server=this;
		final AsyncDtlsServerHandler serverHandler=new AsyncDtlsServerHandler(keystore,keystorePassword,contextMap,channels,server);
		
		bootstrap.handler(new ChannelInitializer<NioDatagramChannel>()
		{
			@Override
			protected void initChannel(NioDatagramChannel socketChannel) throws Exception
			{
				socketChannel.pipeline().addLast(serverHandler);
				socketChannel.pipeline().addLast(new DummyMessageHandler(server));				
			}
		});

		logger.debug("Binding to:" + host + ",port:" + port);
		byte[] address;
		IPAddressType type = IPAddressCompare.getAddressType(host);
		if (type == IPAddressType.IPV4)
			address = IPAddressCompare.textToNumericFormatV4(host);
		else
			address = IPAddressCompare.textToNumericFormatV6(host);

		try
		{
			InetAddress current = InetAddress.getByAddress(address);
			initServerChannels(1, current);
			logger.debug("UDP Listener started");
		}
		catch (Exception ex)
		{
			logger.error("an error occured while starting UDP server, " + ex.getMessage(), ex);
		}
	}
	
	public void terminate()
	{
		logger.debug("Closing UDP listener");
		for (int i = 0; i < serverChannels.size(); i++)
		{
			ChannelFuture channelFuture = serverChannels.get(i).close();
			channelFuture.awaitUninterruptibly();			
		}
		group.shutdownGracefully();
		logger.debug("UDP Listener stopped");
	}
	
	private void initServerChannels(int poolSize, InetAddress current)
	{
		ChannelFuture future = null;
		for (int i = 0; i < poolSize; ++i)
		{
			if (current == null)
				future = bootstrap.bind(new InetSocketAddress("0.0.0.0", port));
			else
				future = bootstrap.bind(new InetSocketAddress(current, port));

			future.awaitUninterruptibly();
			if (!future.isSuccess())
				logger.error("CHANNEL NOT CONNECTED:" + future.cause());

			serverChannels.add(future.channel());
		}
	}

	@Override
	public void messageReceived(String message) 
	{
		messages.add(message);
		messagesCount.incrementAndGet();
	}
	
	public Integer getMessagesReceived()
	{
		return messagesCount.get();
	}

	@Override
	public Integer handshakeMessagesReceived(MessageType messageType) 
	{
		return handshakeHandler.getCount(messageType);
	}
	
	public void sendMessage(InetSocketAddress address, ByteBuf data) throws Exception
	{
		contextMap.getDtlsServerProtocol(keystore,keystorePassword,channels.get(address),address).sendPacket(data);
	}
	
	public Certificate getCertificate(InetSocketAddress address)
	{
		AsyncDtlsServerProtocol protocol=contextMap.getExistingDtlsServerProtocol(address);
		if(protocol==null)
			return null;
		
		return protocol.getClientCertificate();
	}
	
	@Override
	public void handshakeStarted(InetSocketAddress address,Channel channel) 
	{
		logger.info("Handshake started for:" + address);
	}

	@Override
	public void handshakeCompleted(InetSocketAddress address,Channel channel) 
	{
		logger.info("Handshake completed for:" + address);
	}

	@Override
	public void errorOccured(InetSocketAddress address,Channel channel) 
	{
		contextMap.remove(address);
		channels.remove(address, channel);
		channel.close();
	}
	
	@Override
	public String getMessage(Integer index) 
	{
		return messages.get(index);
	}
}