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

import java.util.Hashtable;

import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CertificateStatus;
import org.bouncycastle.crypto.tls.SessionParameters;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsSession;

public class AsyncDtlsClientState 
{
	private TlsClient client = null;
	private AsyncDtlsClientContext clientContext = null;
	private TlsSession tlsSession = null;
	private SessionParameters sessionParameters = null;
	private SessionParameters.Builder sessionParametersBuilder = null;
	private int[] offeredCipherSuites = null;
	private short[] offeredCompressionMethods = null;
	private Hashtable<Integer, byte[]> clientExtensions = null;
	private Hashtable<Integer, byte[]> serverExtensions = null;
	private byte[] selectedSessionID = null;
	private boolean resumedSession = false;
	private boolean secure_renegotiation = false;
	private boolean allowCertificateStatus = false;
	private boolean expectSessionTicket = false;
	private TlsKeyExchange keyExchange = null;
	private TlsAuthentication authentication = null;
	private CertificateStatus certificateStatus = null;
	private CertificateRequest certificateRequest = null;
	private TlsCredentials clientCredentials = null;
	private TlsHandshakeHash handshakeHash = null;
    
	public TlsClient getClient() 
	{
		return client;
	}
	
	public void setClient(TlsClient client) 
	{
		this.client = client;
	}
	
	public AsyncDtlsClientContext getClientContext() 
	{
		return clientContext;
	}
	
	public void setClientContext(AsyncDtlsClientContext clientContext) 
	{
		this.clientContext = clientContext;
	}
	
	public TlsSession getTlsSession() 
	{
		return tlsSession;
	}
	
	public void setTlsSession(TlsSession tlsSession) 
	{
		this.tlsSession = tlsSession;
	}
	
	public SessionParameters getSessionParameters() 
	{
		return sessionParameters;
	}
	
	public void setSessionParameters(SessionParameters sessionParameters) 
	{
		this.sessionParameters = sessionParameters;
	}
	
	public SessionParameters.Builder getSessionParametersBuilder() 
	{
		return sessionParametersBuilder;
	}
	
	public void setSessionParametersBuilder(SessionParameters.Builder sessionParametersBuilder) 
	{
		this.sessionParametersBuilder = sessionParametersBuilder;
	}
	
	public int[] getOfferedCipherSuites() 
	{
		return offeredCipherSuites;
	}
	
	public void setOfferedCipherSuites(int[] offeredCipherSuites) 
	{
		this.offeredCipherSuites = offeredCipherSuites;
	}
	
	public short[] getOfferedCompressionMethods() 
	{
		return offeredCompressionMethods;
	}
	
	public void setOfferedCompressionMethods(short[] offeredCompressionMethods) 
	{
		this.offeredCompressionMethods = offeredCompressionMethods;
	}
	
	public Hashtable<Integer, byte[]> getClientExtensions() 
	{
		return clientExtensions;
	}
	
	public void setClientExtensions(Hashtable<Integer, byte[]> clientExtensions) 
	{
		this.clientExtensions = clientExtensions;
	}
	
	public Hashtable<Integer, byte[]> getServerExtensions() 
	{
		return serverExtensions;
	}
	
	public void setServerExtensions(Hashtable<Integer, byte[]> serverExtensions) 
	{
		this.serverExtensions = serverExtensions;
	}
	
	public byte[] getSelectedSessionID() 
	{
		return selectedSessionID;
	}
	
	public void setSelectedSessionID(byte[] selectedSessionID) 
	{
		this.selectedSessionID = selectedSessionID;
	}
	
	public boolean isResumedSession() 
	{
		return resumedSession;
	}
	
	public void setResumedSession(boolean resumedSession) 
	{
		this.resumedSession = resumedSession;
	}
	
	public boolean isSecure_renegotiation() 
	{
		return secure_renegotiation;
	}
	
	public void setSecure_renegotiation(boolean secure_renegotiation) 
	{
		this.secure_renegotiation = secure_renegotiation;
	}
	
	public boolean isAllowCertificateStatus() 
	{
		return allowCertificateStatus;
	}
	
	public void setAllowCertificateStatus(boolean allowCertificateStatus) 
	{
		this.allowCertificateStatus = allowCertificateStatus;
	}
	
	public boolean isExpectSessionTicket() 
	{
		return expectSessionTicket;
	}
	
	public void setExpectSessionTicket(boolean expectSessionTicket) 
	{
		this.expectSessionTicket = expectSessionTicket;
	}
	
	public TlsKeyExchange getKeyExchange() 
	{
		return keyExchange;
	}
	
	public void setKeyExchange(TlsKeyExchange keyExchange) 
	{
		this.keyExchange = keyExchange;
	}
	
	public TlsAuthentication getAuthentication() 
	{
		return authentication;
	}
	
	public void setAuthentication(TlsAuthentication authentication) 
	{
		this.authentication = authentication;
	}
	
	public CertificateStatus getCertificateStatus() 
	{
		return certificateStatus;
	}
	
	public void setCertificateStatus(CertificateStatus certificateStatus) 
	{
		this.certificateStatus = certificateStatus;
	}
	
	public CertificateRequest getCertificateRequest() 
	{
		return certificateRequest;
	}
	
	public void setCertificateRequest(CertificateRequest certificateRequest) 
	{
		this.certificateRequest = certificateRequest;
	}
	
	public TlsCredentials getClientCredentials() 
	{
		return clientCredentials;
	}
	
	public void setClientCredentials(TlsCredentials clientCredentials) 
	{
		this.clientCredentials = clientCredentials;
	}

	public TlsHandshakeHash getHandshakeHash() 
	{
		return handshakeHash;
	}

	public void setHandshakeHash(TlsHandshakeHash handshakeHash) 
	{
		this.handshakeHash = handshakeHash;
	}				
}
