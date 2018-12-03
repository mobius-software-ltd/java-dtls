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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateStatus;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.ConnectionEnd;
import org.bouncycastle.crypto.tls.EncryptionAlgorithm;
import org.bouncycastle.crypto.tls.ExporterLabel;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.NewSessionTicket;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.SupplementalDataEntry;
import org.bouncycastle.crypto.tls.TlsDSSSigner;
import org.bouncycastle.crypto.tls.TlsECDSASigner;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsRSASigner;
import org.bouncycastle.crypto.tls.TlsSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;

public class AsyncDtlsServerProtocol implements HandshakeHandler
{
	enum State
	{
		INIT, CLIENT_HELLO_RECEIVED, SERVER_HELLO_DONE, SUPP_DATA_RECEIVED, CERTIFICATE_RECEIVED, CLIENT_KEY_EXCHANGE_RECEIVED, CERTIFICATE_VERIFY_RECEIVED, FINISH_RECEIVED, ENDED
	}
	
	private AsyncDtlsServerState serverState;
	private AsyncDtlsRecordLayer recordLayer;
	
	private short sequence=0;
	private State handshakeState=State.INIT;
	
	private HandshakeHandler parentHandler;
	private DtlsStateHandler handler;
	
	private Channel channel;
	private InetSocketAddress remoteAddress;
	private Certificate clientCertificate;
	
	public AsyncDtlsServerProtocol(AsyncDtlsServer server,SecureRandom secureRandom,Channel channel,HandshakeHandler parentHandler,InetSocketAddress address,DtlsStateHandler handler) throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		this.parentHandler=parentHandler;
		this.handler=handler;
	
		this.channel=channel;
		this.remoteAddress=address;
		
		AsyncDtlsServerState state = new AsyncDtlsServerState();
        state.setServer(server);
        state.setSecureRandom(secureRandom);
        
        AsyncDtlsSecurityParameters securityParameters = new AsyncDtlsSecurityParameters();
        securityParameters.setEntity(ConnectionEnd.server);
        state.setSecurityParameters(securityParameters);  
        state.setTlsServerContext(new AsyncDtlsServerContext(secureRandom, securityParameters));
        
        byte[] random=new byte[32];
        state.getTlsServerContext().getNonceRandomGenerator().nextBytes(random);
        securityParameters.setServerRandom(random);
        
        server.initServer(state.getTlsServerContext());
        this.serverState=state;
        
        state.setHandshakeHash(new DeferredHash());
        state.getHandshakeHash().init(state.getTlsServerContext());
        
        recordLayer = new AsyncDtlsRecordLayer(state.getHandshakeHash(), this, channel,state.getTlsServerContext(), server, address, (InetSocketAddress) channel.localAddress());
	}
	
	public Certificate getClientCertificate()
	{
		return clientCertificate;
	}
	
	@SuppressWarnings("unchecked")
	private void postProcessClientHello() throws TlsFatalAlert,IOException
	{
		AsyncDtlsSecurityParameters securityParameters = serverState.getSecurityParameters();
		
        ProtocolVersion serverVersion = serverState.getServer().getServerVersion();
        if (!serverVersion.isEqualOrEarlierVersionOf(serverState.getTlsServerContext().getClientVersion()))
            throw new TlsFatalAlert(AlertDescription.internal_error);

        int selectedCipherSuite = serverState.getServer().getSelectedCipherSuite();
        boolean hasSelectedCipherSuite=false;
        for(int offeredCipherSuite:serverState.getOfferedCipherSuites())
        {
        	if(selectedCipherSuite==offeredCipherSuite)
        	{
        		hasSelectedCipherSuite=true;
        		break;
        	}
        }
        
        boolean hasMinimumVersion=DtlsHelper.getMinimumVersion(selectedCipherSuite).isEqualOrEarlierVersionOf(serverVersion.getEquivalentTLSVersion());
        if (selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL || CipherSuite.isSCSV(selectedCipherSuite) || !hasSelectedCipherSuite || !hasMinimumVersion)
            throw new TlsFatalAlert(AlertDescription.internal_error);
        
        switch (DtlsHelper.getEncryptionAlgorithm(selectedCipherSuite))
        {
        	case EncryptionAlgorithm.RC4_40:
        	case EncryptionAlgorithm.RC4_128:
        		throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        
        short selectedCompressionMethod = serverState.getServer().getSelectedCompressionMethod();
        boolean hasSelectedCompressionMethod=false;
        for(short offeredCompressionMethod:serverState.getOfferedCompressionMethods())
        	if(offeredCompressionMethod==selectedCompressionMethod)
        	{
        		hasSelectedCompressionMethod=true;
        		break;
        	}
        
        if (!hasSelectedCompressionMethod)
            throw new TlsFatalAlert(AlertDescription.internal_error);

        serverState.getTlsServerContext().setServerVersion(serverVersion);
        
        securityParameters.setCipherSuite(selectedCipherSuite);
        securityParameters.setCompressionAlgorithm(selectedCompressionMethod);

        serverState.setServerExtensions(serverState.getServer().getServerExtensions());

        if (serverState.isSecure_renegotiation())
        {        	
            byte[] renegExtData = null;
            if(serverState.getServerExtensions()!=null)
            	serverState.getServerExtensions().get(DtlsHelper.EXT_RenegotiationInfo);
            
            boolean noRenegExt = (null == renegExtData);

            if (noRenegExt)
            {
            	if(serverState.getServerExtensions()==null)
            		serverState.setServerExtensions(new Hashtable<Integer,byte[]>());
                
            	serverState.getServerExtensions().put(DtlsHelper.EXT_RenegotiationInfo,DtlsHelper.EMPTY_BYTES_WITH_LENGTH);
            }
        }

        if (securityParameters.isExtendedMasterSecret())
        {
            if(serverState.getServerExtensions()==null)
        		serverState.setServerExtensions(new Hashtable<Integer,byte[]>());
            
            serverState.getServerExtensions().put(DtlsHelper.EXT_extended_master_secret, DtlsHelper.EMPTY_BYTES);            
        }

        if (serverState.getServerExtensions() != null)
        {
        	Boolean encryptThenMac=false;
        	byte[] extensionData=serverState.getServerExtensions().get(DtlsHelper.EXT_encrypt_then_mac);
        	if(extensionData!=null)
        	{
        		if (extensionData.length != 0)
        			throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            
        		encryptThenMac = true;
        	}
        	
            securityParameters.setEncryptThenMAC(encryptThenMac);
            securityParameters.setMaxFragmentLength(DtlsHelper.evaluateMaxFragmentLengthExtension(serverState.isResumedSession(), serverState.getClientExtensions(), serverState.getServerExtensions(), AlertDescription.internal_error));
            
            Boolean truncatedHMAC=false;
            
        	extensionData=serverState.getServerExtensions().get(DtlsHelper.EXT_truncated_hmac);
        	if(extensionData!=null)
        	{
        		if (extensionData.length != 0)
        			throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            
        		truncatedHMAC = true;
        	}
        	
            securityParameters.setTruncatedHMac(truncatedHMAC);

            byte[] extension_data = serverState.getServerExtensions().get(DtlsHelper.EXT_status_request);
            if(extension_data!=null && extension_data.length!=0)
            	throw new TlsFatalAlert(AlertDescription.internal_error);
            
            Boolean hasEmptyStatusRequest=extension_data!=null;
            
            extension_data = serverState.getServerExtensions().get(DtlsHelper.EXT_SessionTicket);
            if(extension_data!=null && extension_data.length!=0)
            	throw new TlsFatalAlert(AlertDescription.internal_error);
            
            Boolean hasEmptySessionTicket=extension_data!=null;
            
            serverState.setAllowCertificateStatus(!serverState.isResumedSession() && hasEmptyStatusRequest);
            serverState.setExpectSessionTicket(!serverState.isResumedSession() && hasEmptySessionTicket);            
        }

        securityParameters.setPrfAlgorithm(DtlsHelper.getPRFAlgorithm(serverState.getTlsServerContext().getServerVersion(),securityParameters.getCipherSuite()));
        securityParameters.setVerifyDataLength(12);

        Integer totalLength=6+securityParameters.getServerRandom().length+DtlsHelper.calculateExtensionsLength(serverState.getServerExtensions());
        ProtocolVersion recordLayerVersion = serverState.getTlsServerContext().getServerVersion();
        recordLayer.setReadVersion(recordLayerVersion);
        recordLayer.setWriteVersion(recordLayerVersion);
        
        if(handshakeState!=State.CLIENT_HELLO_RECEIVED)
        {
        	int capacity = DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + 35;
	        ByteBuf data=Unpooled.buffer(capacity);
	        short currSequence=sequence++;
	        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.HELLO_VERIFY_REQUEST,data,35);
	        data.writeByte(recordLayerVersion.getMajorVersion());
	        data.writeByte(recordLayerVersion.getMinorVersion());
	        data.writeByte(serverState.getSecurityParameters().getCookie().length);
	        data.writeBytes(serverState.getSecurityParameters().getCookie());
	        recordLayer.send(currSequence,MessageType.HELLO_VERIFY_REQUEST, data);
	        serverState.getHandshakeHash().reset();
        	return;
        }
        
        ByteBuf output=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + totalLength);
        short currSequence=sequence++;
        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.SERVER_HELLO,output,totalLength);
        output.writeByte(serverVersion.getMajorVersion());
        output.writeByte(serverVersion.getMinorVersion());
        output.writeBytes(securityParameters.getServerRandom());
        output.writeByte(DtlsHelper.EMPTY_BYTES.length);
        output.writeShort(selectedCipherSuite);
        output.writeByte(selectedCompressionMethod);

        if (serverState.getServerExtensions() != null)
        	DtlsHelper.writeExtensions(output, serverState.getServerExtensions());
        
        short maxFragmentLength=serverState.getSecurityParameters().getMaxFragmentLength();
        if (maxFragmentLength >= 0)
        {
            if (!MaxFragmentLength.isValid(maxFragmentLength))
                throw new TlsFatalAlert(AlertDescription.internal_error); 
        
            int plainTextLimit = 1 << (8 + maxFragmentLength);
            serverState.setPlainTextLimit(plainTextLimit);
        }
        
        recordLayer.send(currSequence,MessageType.SERVER_HELLO, output);
        serverState.setHandshakeHash(serverState.getHandshakeHash().notifyPRFDetermined());
        
        Vector<SupplementalDataEntry> serverSupplementalData = serverState.getServer().getServerSupplementalData();
        if (serverSupplementalData != null)
        {
        	totalLength=3+DtlsHelper.calculateSupplementalDataLength(serverSupplementalData);
            ByteBuf supplementalDataOutput = Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + totalLength);
            currSequence=sequence++;
            DtlsHelper.writeHandshakeHeader(currSequence,MessageType.SUPPLEMENTAL_DATA,supplementalDataOutput,totalLength);
            DtlsHelper.writeSupplementalData(supplementalDataOutput,serverSupplementalData);
            recordLayer.send(currSequence,MessageType.SUPPLEMENTAL_DATA,supplementalDataOutput);
        }
        
        serverState.setKeyExchange(serverState.getServer().getKeyExchange());
        serverState.getKeyExchange().init(serverState.getTlsServerContext());
        serverState.setServerCredentials(serverState.getServer().getCredentials());
        Certificate serverCertificate = null;

        if (serverState.getServerCredentials() == null)
        	serverState.getKeyExchange().skipServerCredentials();
        else
        {
        	serverState.getKeyExchange().processServerCredentials(serverState.getServerCredentials());
            serverCertificate = serverState.getServerCredentials().getCertificate();
            currSequence=sequence++;
            ByteBuf certificateOutput = DtlsHelper.writeCertificateList(currSequence,serverCertificate.getCertificateList());
            recordLayer.send(currSequence,MessageType.CERTIFICATE,certificateOutput);
        }
        
        if (serverCertificate == null || serverCertificate.isEmpty())
            serverState.setAllowCertificateStatus(false);
        else
        	serverState.setAllowCertificateStatus(true);
        
        if (serverState.isAllowCertificateStatus())
        {
            CertificateStatus certificateStatus = serverState.getServer().getCertificateStatus();
            if (certificateStatus != null)
            {
            	currSequence=sequence++;
                ByteBuf certificateStatusOutput = DtlsHelper.writeCertificateStatus(currSequence,certificateStatus);
                recordLayer.send(currSequence,MessageType.CERTIFICATE_STATUS, certificateStatusOutput);                
            }
        }
        
        byte[] serverKeyExchange = serverState.getKeyExchange().generateServerKeyExchange();
        if (serverKeyExchange != null)
        {
        	ByteBuf keyExchangeOutput=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + serverKeyExchange.length);
        	currSequence=sequence++;
        	DtlsHelper.writeHandshakeHeader(currSequence,MessageType.SERVER_KEY_EXCHANGE,keyExchangeOutput,serverKeyExchange.length);
        	keyExchangeOutput.writeBytes(serverKeyExchange);
            recordLayer.send(currSequence,MessageType.SERVER_KEY_EXCHANGE, keyExchangeOutput);
        }

        if (serverState.getServerCredentials() != null)
        {
            serverState.setCertificateRequest(serverState.getServer().getCertificateRequest());
            if (serverState.getCertificateRequest() != null)
            {            	
                if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(serverState.getTlsServerContext().getServerVersion().getEquivalentTLSVersion()) != (serverState.getCertificateRequest().getSupportedSignatureAlgorithms() != null))
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                
                serverState.getKeyExchange().validateCertificateRequest(serverState.getCertificateRequest());

                ByteBuf certificateRequestOutput;
                AsyncCertificateRequest requestWrapper = new AsyncCertificateRequest(serverState.getCertificateRequest().getCertificateTypes(),serverState.getCertificateRequest().getSupportedSignatureAlgorithms(),serverState.getCertificateRequest().getCertificateAuthorities());
                currSequence=sequence++;
                certificateRequestOutput=requestWrapper.encode(currSequence);
                recordLayer.send(currSequence,MessageType.CERTIFICATE_REQUEST, certificateRequestOutput);
                
                if (requestWrapper.getSupportedSignatureAlgorithms() != null)
                {
                    for (int i = 0; i < requestWrapper.getSupportedSignatureAlgorithms().size(); ++i)
                    {
                        SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm)requestWrapper.getSupportedSignatureAlgorithms().elementAt(i);
                        short hashAlgorithm = signatureAndHashAlgorithm.getHash();
                        if (!HashAlgorithm.isPrivate(hashAlgorithm))
                        	serverState.getHandshakeHash().trackHashAlgorithm(hashAlgorithm);                        
                    }
                }
            }
        }

        ByteBuf emptyBuffer=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH);
        currSequence=sequence++;
        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.SERVER_HELLO_DONE,emptyBuffer,0);    	
        recordLayer.send(currSequence,MessageType.SERVER_HELLO_DONE, emptyBuffer);
	}
	
	private void postProcessClientFinished() throws TlsFatalAlert,IOException
	{		
		if (serverState.isExpectSessionTicket())
        {
            NewSessionTicket newSessionTicket = serverState.getServer().getNewSessionTicket();
            int length=DtlsHelper.calculateNewTicketLength(newSessionTicket);
            ByteBuf sessionTicketBuffer=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + length);
            short currSequence=sequence++;
            DtlsHelper.writeHandshakeHeader(currSequence,MessageType.SESSION_TICKET,sessionTicketBuffer,length);
            DtlsHelper.writeNewTicket(sessionTicketBuffer, newSessionTicket);
            recordLayer.send(currSequence,MessageType.SESSION_TICKET, sessionTicketBuffer);
        }

		byte[] serverVerifyData = DtlsHelper.calculateVerifyData(serverState.getTlsServerContext(), ExporterLabel.server_finished,DtlsHelper.getCurrentPRFHash(serverState.getTlsServerContext(), serverState.getHandshakeHash(), null));
        ByteBuf serverVerifyBuffer=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + serverVerifyData.length);
        short currSequence=sequence++;
        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.FINISHED,serverVerifyBuffer,serverVerifyData.length);
        serverVerifyBuffer.writeBytes(serverVerifyData);
        recordLayer.send(currSequence,MessageType.FINISHED, serverVerifyBuffer);
        recordLayer.handshakeSuccessful();
        serverState.getServer().notifyHandshakeComplete();        
	}
	
	public void sendAlert(short alertLevel,short alertDescription,String message,Throwable cause) throws IOException
	{
		recordLayer.sendAlert(alertLevel, alertDescription, message, cause);
	}
	
	public void sendPacket(ByteBuf data) throws IOException
	{
		recordLayer.send(data);
	}
	
	public List<ByteBuf> receivePacket(ByteBuf data) throws IOException
	{
		return recordLayer.receive(data);
	}
	
	public void handleHandshake(MessageType messageType,ByteBuf data) throws IOException
	{
		if(parentHandler!=null)
			parentHandler.handleHandshake(messageType, data);
		
		switch(messageType)
		{
			case CLIENT_HELLO:
				if(handshakeState!=State.INIT)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				//receive message
				Boolean started=processClientHello(data);
				if(started)
				{
					handshakeState=State.CLIENT_HELLO_RECEIVED;
					
					if(handler!=null)
						handler.handshakeStarted(remoteAddress, channel);
				}
		        break;
			case SUPPLEMENTAL_DATA:
				if(handshakeState!=State.SERVER_HELLO_DONE)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processSupplementalData(data);
				handshakeState=State.SUPP_DATA_RECEIVED;
				break;
			case CERTIFICATE:
				if(handshakeState!=State.SERVER_HELLO_DONE && handshakeState!=State.SUPP_DATA_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				if(handshakeState==State.SERVER_HELLO_DONE)
				{	
					serverState.getServer().processClientSupplementalData(null);
					handshakeState=State.SUPP_DATA_RECEIVED;
				}	
				
				processCertificate(data);
				handshakeState=State.CERTIFICATE_RECEIVED;
				break;			
			case CLIENT_KEY_EXCHANGE:
				if(handshakeState!=State.SERVER_HELLO_DONE && handshakeState!=State.SUPP_DATA_RECEIVED && handshakeState!=State.CERTIFICATE_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				if(handshakeState==State.SERVER_HELLO_DONE)
				{	
					serverState.getServer().processClientSupplementalData(null);
					handshakeState=State.SUPP_DATA_RECEIVED;
				}
				
				if(handshakeState==State.SUPP_DATA_RECEIVED)
				{
					if (serverState.getCertificateRequest() == null)
			            serverState.getKeyExchange().skipClientCredentials();
			        else
			        {
			        	if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(serverState.getTlsServerContext().getServerVersion().getEquivalentTLSVersion()))
		                    throw new TlsFatalAlert(AlertDescription.unexpected_message);

		                if (serverState.getClientCertificate() != null)
		                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
		                
		                serverState.setClientCertificate(Certificate.EMPTY_CHAIN);

		                if (serverState.getClientCertificate().isEmpty())
		                	serverState.getKeyExchange().skipClientCredentials();
		                else
		                {
		                    serverState.setClientCertificateType(DtlsHelper.getClientCertificateType(serverState.getClientCertificate(),serverState.getServerCredentials().getCertificate()));
		                    serverState.getKeyExchange().processClientCertificate(serverState.getClientCertificate());
		                }

		                serverState.getServer().notifyClientCertificate(serverState.getClientCertificate());
			        }
					
					handshakeState=State.CERTIFICATE_RECEIVED;
				}
				
				processClientKeyExchange(data);
				handshakeState=State.CLIENT_KEY_EXCHANGE_RECEIVED;
				break;
			case CERTIFICATE_VERIFY:
				if(handshakeState!=State.CLIENT_KEY_EXCHANGE_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);

				processCertificateVerify(data);
				handshakeState=State.CERTIFICATE_VERIFY_RECEIVED;
				break;
			case FINISHED:
				if(handshakeState!=State.CERTIFICATE_VERIFY_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);

				byte[] expectedClientVerifyData = DtlsHelper.calculateVerifyData(serverState.getTlsServerContext(), ExporterLabel.client_finished, DtlsHelper.getCurrentPRFHash(serverState.getTlsServerContext(), serverState.getHandshakeHash(), null));
				processFinished(data, expectedClientVerifyData);
				handshakeState=State.FINISH_RECEIVED;										
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.unexpected_message);				
		}
	}
	
	public void postProcessHandshake(MessageType messageType,ByteBuf data) throws IOException
	{
		if(parentHandler!=null)
			parentHandler.postProcessHandshake(messageType, data);
		
		switch(messageType)
		{
			case CLIENT_HELLO:
				postProcessClientHello();				
				if(handshakeState==State.CLIENT_HELLO_RECEIVED)
				{
					handshakeState=State.SERVER_HELLO_DONE;
					serverState.getHandshakeHash().sealHashAlgorithms();
				}
		        break;
			case CLIENT_KEY_EXCHANGE:
				serverState.setPrepareToFinishHash(serverState.getHandshakeHash());
		        //serverState.setHandshakeHash(serverState.getHandshakeHash().stopTracking());
		        
		        serverState.getSecurityParameters().setSessionHash(DtlsHelper.getCurrentPRFHash(serverState.getTlsServerContext(), serverState.getPrepareToFinishHash(), null));
		        
		        DtlsHelper.establishMasterSecret(serverState.getTlsServerContext().getSecurityParameters(), serverState.getTlsServerContext(), serverState.getKeyExchange());
		        recordLayer.initPendingEpoch(serverState.getServer().getCipher());
		        
		        Boolean hasSigningCapabilities=false;
		        switch (serverState.getClientCertificateType())
		        {
			        case ClientCertificateType.dss_sign:
			        case ClientCertificateType.ecdsa_sign:
			        case ClientCertificateType.rsa_sign:
			        	hasSigningCapabilities = true;
		        }
		        
		        if(serverState.getClientCertificateType() < 0 || !hasSigningCapabilities)
		        	handshakeState=State.CERTIFICATE_VERIFY_RECEIVED;	
		        break;
			case FINISHED:
				postProcessClientFinished();
				handshakeState=State.ENDED;
				
				if(handler!=null)
					handler.handshakeCompleted(remoteAddress, channel);								
				break;
			default:
				break;				
		}
	}
	
	private Boolean processClientHello(ByteBuf body) throws IOException
	{
	    ProtocolVersion client_version = ProtocolVersion.get(body.readByte() & 0xFF, body.readByte() & 0xFF);
	    if (!client_version.isDTLS())
	    	throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	        
	    byte[] client_random = new byte[32];
	    body.readBytes(client_random);
	    
	    short sessionIDLength=body.readUnsignedByte();
	    byte[] sessionID = new byte[sessionIDLength];
	    body.readBytes(sessionID);
	    
	    if (sessionID.length > 32)
	    	throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	        
	    short cookieLength=body.readUnsignedByte();
	    byte[] cookie = new byte[cookieLength];
	    body.readBytes(cookie);
	    
	    Boolean result = true;
	    if(cookieLength==0)
	    {
	    	//need to send hello verify request
	    	cookie=new byte[32];
	    	serverState.getSecureRandom().nextBytes(cookie);
	    	serverState.getSecurityParameters().setCookie(cookie);
	    	result = false;
	    }
	    else
	    {
	    	if(serverState.getSecurityParameters().getCookie()==null)
	    		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	    	
	    	if(!Arrays.equals(cookie, serverState.getSecurityParameters().getCookie()))
	    		throw new TlsFatalAlert(AlertDescription.illegal_parameter);	    	
	    }	
	    
	    int cipher_suites_length = body.readUnsignedShort();
	    if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
	    	throw new TlsFatalAlert(AlertDescription.decode_error);
	        
	    int[] offeredCipherSuites=new int[cipher_suites_length / 2];
	    for(int i=0;i<offeredCipherSuites.length;i++)
	    	offeredCipherSuites[i]=body.readUnsignedShort();
	    
	    serverState.setOfferedCipherSuites(offeredCipherSuites);
	    int compression_methods_length = body.readUnsignedByte();
	    if (compression_methods_length < 1)
	    	throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	    
	    short[] offeredCompressionMethods=new short[compression_methods_length];
	    for(int i=0;i<offeredCompressionMethods.length;i++)
	    	offeredCompressionMethods[i]=body.readUnsignedByte();
	    
	    serverState.setOfferedCompressionMethods(offeredCompressionMethods);
	    
	    Hashtable<Integer, byte[]> extentions=new Hashtable<Integer,byte[]>();
	    int remainingLength=0;
	    if(body.readableBytes()>0)
	    	remainingLength=body.readUnsignedShort();
	    
	    while(remainingLength>0)
	    {
	    	Integer extensionType = body.readUnsignedShort();
	    	byte[] extentionData=new byte[body.readUnsignedShort()];
	    	body.readBytes(extentionData);
	    	extentions.put(extensionType, extentionData);
	    	remainingLength-=4+extentionData.length;
	    }
	    
	    serverState.setClientExtensions(extentions);

	    AsyncDtlsSecurityParameters securityParameters = serverState.getSecurityParameters();
	    
	    byte[] extensionData = serverState.getClientExtensions().get(DtlsHelper.EXT_extended_master_secret);
	    if (extensionData!=null && extensionData.length != 0)
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        
	    
	    securityParameters.setExtendedMasterSecret(extensionData != null);
	    serverState.getTlsServerContext().setClientVersion(client_version);
	    serverState.getServer().notifyClientVersion(client_version);
	    
	    Boolean hasTlsFallbackCSV=false;
	    for(int i=0;i<serverState.getOfferedCipherSuites().length;i++)
	    	if(serverState.getOfferedCipherSuites()[i]==CipherSuite.TLS_FALLBACK_SCSV)
	    	{
	    		hasTlsFallbackCSV=true;
	    		break;
	    	}
	    
	    serverState.getServer().notifyFallback(hasTlsFallbackCSV);
	    securityParameters.setClientRandom(client_random);
	    serverState.getServer().notifyOfferedCipherSuites(serverState.getOfferedCipherSuites());
	    serverState.getServer().notifyOfferedCompressionMethods(serverState.getOfferedCompressionMethods());

	    boolean hasEmptyRenegotiationInfo=false;
	    for(int i=0;i<serverState.getOfferedCipherSuites().length;i++)
	    	if(serverState.getOfferedCipherSuites()[i]==CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
	    	{
	    		hasEmptyRenegotiationInfo=true;
	    		break;
	    	}
	    
	    if (hasEmptyRenegotiationInfo)
            serverState.setSecure_renegotiation(true);
        	    
	    byte[] renegExtData = serverState.getClientExtensions().get(DtlsHelper.EXT_RenegotiationInfo);
        if (renegExtData != null)
        {
        	serverState.setSecure_renegotiation(true);            
            if (!Arrays.equals(renegExtData, DtlsHelper.EMPTY_BYTES_WITH_LENGTH))
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        if(serverState.isSecure_renegotiation())
        	serverState.getServer().notifySecureRenegotiation(serverState.isSecure_renegotiation());
        
        if (serverState.getClientExtensions() != null)
	    {
        	//validating padding extentions
        	extensionData = serverState.getClientExtensions().get(DtlsHelper.EXT_padding);
        	if(extensionData!=null)
        	{
        		for (int i = 0; i < extensionData.length; ++i)
        		{
        			if (extensionData[i] != 0)
        				throw new TlsFatalAlert(AlertDescription.illegal_parameter);	                 
        		}	        	 
        	}
        	 
        	serverState.getServer().processClientExtensions(serverState.getClientExtensions());
	    }
        
        return result;
	}
	
	private void processSupplementalData(ByteBuf body) throws IOException
	{
		Vector<SupplementalDataEntry> clientSupplementalData=new Vector<SupplementalDataEntry>();
		
		int remainingLength=body.readByte()<<16 | body.readByte()<<8 | body.readByte();
		while (remainingLength > 0)
		{
			int suppDataType=body.readUnsignedShort();
			byte[] data = new byte[body.readUnsignedShort()];
			body.readBytes(data);
			clientSupplementalData.addElement(new SupplementalDataEntry(suppDataType, data));
			remainingLength-=4+data.length;
		}
	        
        serverState.getServer().processClientSupplementalData(clientSupplementalData);
	}
	
	private void processCertificate(ByteBuf body) throws IOException
	{
        clientCertificate = DtlsHelper.parseCertificate(body);
        if (serverState.getCertificateRequest() == null)
        {
            throw new IllegalStateException();
        }

        if (serverState.getClientCertificate() != null)
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        
        serverState.setClientCertificate(clientCertificate);
        if (clientCertificate.isEmpty())
            serverState.getKeyExchange().skipClientCredentials();
        else
        {
        	serverState.setClientCertificateType(DtlsHelper.getClientCertificateType(clientCertificate,serverState.getServerCredentials().getCertificate()));
            serverState.getKeyExchange().processClientCertificate(clientCertificate);
        }

        serverState.getServer().notifyClientCertificate(clientCertificate);
	}
	
	private void processClientKeyExchange(ByteBuf body) throws IOException
	{
		//can not parse with byte buffer , needs input stream
		byte[] backedData=new byte[body.readableBytes()];
		body.readBytes(backedData);
		ByteArrayInputStream buf = new ByteArrayInputStream(backedData);
        serverState.getKeyExchange().processClientKeyExchange(buf);
	}
	
	@SuppressWarnings("unchecked")
	private void processCertificateVerify(ByteBuf body) throws IOException
	{
		if (serverState.getCertificateRequest() == null)
            throw new IllegalStateException();
        
		SignatureAndHashAlgorithm signatureAlgorithm=null;
		if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(serverState.getTlsServerContext().getServerVersion().getEquivalentTLSVersion()))
			signatureAlgorithm=DtlsHelper.parseSignatureAndHashAlgorithm(body);
		
		byte[] signature = new byte[body.readUnsignedShort()];
		body.readBytes(signature);
		
		try
        {
            byte[] hash;            
            if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(serverState.getTlsServerContext().getServerVersion().getEquivalentTLSVersion()))
            {
                DtlsHelper.verifySupportedSignatureAlgorithm(serverState.getCertificateRequest().getSupportedSignatureAlgorithms(), signatureAlgorithm);
                hash = serverState.getPrepareToFinishHash().getFinalHash(signatureAlgorithm.getHash());            	             
            }
            else
            	hash = serverState.getTlsServerContext().getSecurityParameters().getSessionHash();
            
            org.bouncycastle.asn1.x509.Certificate x509Cert = serverState.getClientCertificate().getCertificateAt(0);
            SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
            AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);

            TlsSigner tlsSigner;
            switch (serverState.getClientCertificateType())
            {
	            case ClientCertificateType.dss_sign:
	            	tlsSigner = new TlsDSSSigner();
	            	break;
	            case ClientCertificateType.ecdsa_sign:
	            	tlsSigner = new TlsECDSASigner();
	            	break;
	            case ClientCertificateType.rsa_sign:
	            	tlsSigner = new TlsRSASigner();
	            	break;
	            default:
	                throw new IllegalArgumentException("'clientCertificateType' is not a type with signing capability");
            }
            
            tlsSigner.init(serverState.getTlsServerContext());
            if (!tlsSigner.verifyRawSignature(signatureAlgorithm, signature, publicKey, hash))
                throw new TlsFatalAlert(AlertDescription.decrypt_error);            
        }
        catch (TlsFatalAlert e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new TlsFatalAlert(AlertDescription.decrypt_error, e);
        }
	}
	
	private void processFinished(ByteBuf body,byte[] expectedClientVerifyData) throws IOException
	{
		if(body.readableBytes()!=expectedClientVerifyData.length)
			throw new TlsFatalAlert(AlertDescription.handshake_failure);
		
		byte[] clientVerifyData=new byte[body.readableBytes()];
		body.readBytes(clientVerifyData);
		
		if(!Arrays.equals(clientVerifyData, expectedClientVerifyData))
			throw new TlsFatalAlert(AlertDescription.handshake_failure);				
	}
}