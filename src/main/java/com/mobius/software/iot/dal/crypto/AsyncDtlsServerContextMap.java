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

import io.netty.channel.Channel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AsyncDtlsServerContextMap 
{
	private static final Logger logger = LogManager.getLogger(AsyncDtlsServerContextMap.class);
    
	private ConcurrentHashMap<SocketAddress, AsyncDtlsServerProtocol> contextMap=new ConcurrentHashMap<SocketAddress,AsyncDtlsServerProtocol>();
	private SecureRandom SECURE_RANDOM = new SecureRandom();

	private HandshakeHandler parentHandler;
	private DtlsStateHandler handler;
	private String alias=null;
	
	public AsyncDtlsServerContextMap(HandshakeHandler parentHandler,DtlsStateHandler handler)
	{
		this.parentHandler=parentHandler;
		this.handler=handler;
	}
	
	public AsyncDtlsServerContextMap(HandshakeHandler parentHandler,DtlsStateHandler handler,String alias)
	{
		this.parentHandler=parentHandler;
		this.handler=handler;
		this.alias=alias;
	}
	
	public AsyncDtlsServerProtocol getExistingDtlsServerProtocol(InetSocketAddress address)
	{
		return contextMap.get(address);
	}
	
	public AsyncDtlsServerProtocol getDtlsServerProtocol(KeyStore keystore,String keystorePassword,Channel channel,InetSocketAddress address) throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		AsyncDtlsServerProtocol server=contextMap.get(address);
		if(server==null)
		{			
			server=new AsyncDtlsServerProtocol(new AsyncDtlsServer(keystore, keystorePassword, alias),SECURE_RANDOM, channel, parentHandler,address,handler);			
			AsyncDtlsServerProtocol oldServer=contextMap.putIfAbsent(address, server);
			if(oldServer!=null)
				server=oldServer;
		}
		
		return server;
	}
	
	public AsyncDtlsServerProtocol remove(SocketAddress address)
	{
		return contextMap.remove(address);
	}
	
	public void cleanupInactiveChannels(Long period) 
	{
		Long checkTime=System.currentTimeMillis()-period;
		Iterator<Entry<SocketAddress, AsyncDtlsServerProtocol>> iterator=contextMap.entrySet().iterator();
		while(iterator.hasNext())
		{
			Entry<SocketAddress, AsyncDtlsServerProtocol> currEntry=iterator.next();			
			if(currEntry.getValue()==null || currEntry.getValue().getLastActivity()<checkTime)
			{
				logger.warn("Removing " + currEntry.getKey() + " Map due to inactivity timeout");
				remove(currEntry.getKey());
			}
		}
	}
}