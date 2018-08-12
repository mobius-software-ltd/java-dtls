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

import java.security.SecureRandom;
import java.util.Hashtable;

import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.SessionParameters;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsServer;
import org.bouncycastle.crypto.tls.TlsSession;

public class AsyncDtlsServerState 
{
	private TlsServer server = null;
	private SecureRandom secureRandom;
	private AsyncDtlsSecurityParameters securityParameters;
	private TlsSession tlsSession = null;
	private SessionParameters sessionParameters = null;
	private SessionParameters.Builder sessionParametersBuilder = null;
	private int[] offeredCipherSuites = null;
	private short[] offeredCompressionMethods = null;
	private Hashtable<Integer, byte[]> clientExtensions = null;
	private Hashtable<Integer, byte[]> serverExtensions = null;
	private boolean resumedSession = false;
	private boolean secure_renegotiation = false;
	private boolean allowCertificateStatus = false;
	private boolean expectSessionTicket = false;
	private TlsKeyExchange keyExchange = null;
	private TlsCredentials serverCredentials = null;
	private CertificateRequest certificateRequest = null;
	private short clientCertificateType = -1;
	private Certificate clientCertificate = null;
    private Integer plainTextLimit = null;
    private AsyncDtlsServerContext tlsServerContext = null;
    private TlsHandshakeHash handshakeHash = null;
    private TlsHandshakeHash prepareToFinishHash = null;
    
	public TlsServer getServer() 
	{
		return server;
	}
	
	public void setServer(TlsServer server) 
	{
		this.server = server;
	}	
		
	public AsyncDtlsServerContext getTlsServerContext() 
	{
		return tlsServerContext;
	}

	public void setTlsServerContext(AsyncDtlsServerContext tlsServerContext) 
	{
		this.tlsServerContext = tlsServerContext;
	}

	public SecureRandom getSecureRandom() 
	{
		return secureRandom;
	}

	public void setSecureRandom(SecureRandom secureRandom) 
	{
		this.secureRandom = secureRandom;
	}

	public AsyncDtlsSecurityParameters getSecurityParameters() 
	{
		return securityParameters;
	}

	public void setSecurityParameters(AsyncDtlsSecurityParameters securityParameters) 
	{
		this.securityParameters = securityParameters;
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
	
	public Hashtable<Integer,byte[]> getClientExtensions() 
	{
		return clientExtensions;
	}
	
	public void setClientExtensions(Hashtable<Integer,byte[]> clientExtensions) 
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
	
	public TlsCredentials getServerCredentials() 
	{
		return serverCredentials;
	}
	
	public void setServerCredentials(TlsCredentials serverCredentials) 
	{
		this.serverCredentials = serverCredentials;
	}
	
	public CertificateRequest getCertificateRequest() 
	{
		return certificateRequest;
	}
	
	public void setCertificateRequest(CertificateRequest certificateRequest) 
	{
		this.certificateRequest = certificateRequest;
	}
	
	public short getClientCertificateType() 
	{
		return clientCertificateType;
	}
	
	public void setClientCertificateType(short clientCertificateType) 
	{
		this.clientCertificateType = clientCertificateType;
	}
	
	public Certificate getClientCertificate() 
	{
		return clientCertificate;
	}
	
	public void setClientCertificate(Certificate clientCertificate) 
	{
		this.clientCertificate = clientCertificate;
	}

	public Integer getPlainTextLimit() 
	{
		return plainTextLimit;
	}

	public void setPlainTextLimit(Integer plainTextLimit) 
	{
		this.plainTextLimit = plainTextLimit;
	}

	public TlsHandshakeHash getHandshakeHash() 
	{
		return handshakeHash;
	}

	public void setHandshakeHash(TlsHandshakeHash handshakeHash) 
	{
		this.handshakeHash = handshakeHash;
	}

	public TlsHandshakeHash getPrepareToFinishHash() 
	{
		return prepareToFinishHash;
	}

	public void setPrepareToFinishHash(TlsHandshakeHash prepareToFinishHash) 
	{
		this.prepareToFinishHash = prepareToFinishHash;
	}		
}