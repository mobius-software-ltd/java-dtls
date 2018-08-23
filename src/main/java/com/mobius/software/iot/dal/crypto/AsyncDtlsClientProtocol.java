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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.CipherType;
import org.bouncycastle.crypto.tls.CompressionMethod;
import org.bouncycastle.crypto.tls.ConnectionEnd;
import org.bouncycastle.crypto.tls.EncryptionAlgorithm;
import org.bouncycastle.crypto.tls.ExporterLabel;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.NewSessionTicket;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.SessionParameters;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.SupplementalDataEntry;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

public class AsyncDtlsClientProtocol implements HandshakeHandler
{
	enum State
	{
		INIT, CLIENT_HELLO_SENT, SERVER_HELLO_RECEIVED, SUPP_DATA_RECEIVED, CERTIFICATE_RECEIVED, CERTIFICATE_STATUS_RECEIVED, SERVER_KEY_EXCHANGE_RECEIVED, CERTIFICATE_REQUEST_RECEIVED, SERVER_HELLO_DONE, FINISH_SENT, SESSION_TICKET_RECEIVED,ENDED
	}
	
	private AsyncDtlsClientState clientState;
	private AsyncDtlsRecordLayer recordLayer;
	
	private State handshakeState=State.INIT;
	private Certificate serverCertificate;
	
	private short sequence=0;	
	private HandshakeHandler parentHandler;
	private DtlsStateHandler handler;
	
	private Channel channel;
	private InetSocketAddress remoteAddress;
	
	public AsyncDtlsClientProtocol(AsyncDtlsClient client,SecureRandom secureRandom,Channel channel,HandshakeHandler parentHandler,DtlsStateHandler handler,InetSocketAddress address,boolean useExtendedMasterSecret) throws UnrecoverableKeyException, CertificateEncodingException, KeyStoreException, NoSuchAlgorithmException, IOException
	{
		this.parentHandler=parentHandler;
		this.handler=handler;
	
		this.channel=channel;
		this.remoteAddress=address;
		
		AsyncDtlsSecurityParameters securityParameters = new AsyncDtlsSecurityParameters();
        securityParameters.setEntity(ConnectionEnd.client);

        clientState = new AsyncDtlsClientState();
        clientState.setClient(client);
        clientState.setClientContext(new AsyncDtlsClientContext(secureRandom, securityParameters));

        securityParameters.setExtendedMasterSecret(useExtendedMasterSecret);
        securityParameters.setClientRandom(DtlsHelper.createRandomBlock(client.shouldUseGMTUnixTime(),clientState.getClientContext().getNonceRandomGenerator()));
        client.initClient(clientState.getClientContext());

        clientState.setHandshakeHash(new DeferredHash());       
    	clientState.getHandshakeHash().init(clientState.getClientContext());
        
        recordLayer = new AsyncDtlsRecordLayer(clientState.getHandshakeHash(), this, channel,clientState.getClientContext(), client, address);
	}
	
	public Certificate getServerCertificate()
	{
		return this.serverCertificate;
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
	
	@SuppressWarnings("unchecked")
	public void initHandshake(byte[] cookie) throws IOException
	{
		SecurityParameters securityParameters = clientState.getClientContext().getSecurityParameters();
        
		ProtocolVersion client_version = clientState.getClient().getClientVersion();
        if (!client_version.isDTLS())
            throw new TlsFatalAlert(AlertDescription.internal_error);
        
        AsyncDtlsClientContext context = clientState.getClientContext();
        context.setClientVersion(client_version);
        
        boolean fallback = clientState.getClient().isFallback();

        //Cipher suites
        clientState.setOfferedCipherSuites(clientState.getClient().getCipherSuites());

        // Integer -> byte[]
        clientState.setClientExtensions(clientState.getClient().getClientExtensions());
        
        byte[] renegExtData = clientState.getClientExtensions().get(DtlsHelper.EXT_RenegotiationInfo);
        boolean noRenegExt = (null == renegExtData);
        boolean noRenegSCSV = true;
        for(int i=0;i<clientState.getOfferedCipherSuites().length;i++)
        	if(clientState.getOfferedCipherSuites()[i]==CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        	{
        		noRenegSCSV=false;
        		break;
        	}
        
        boolean tlsFallbackFound=false;
        for(int i=0;i<clientState.getOfferedCipherSuites().length;i++)
        	if(clientState.getOfferedCipherSuites()[i]==CipherSuite.TLS_FALLBACK_SCSV)
        	{
        		tlsFallbackFound=true;
        		break;
        	}
        
        int additionalCount=0;
        if (noRenegExt && noRenegSCSV)
            additionalCount++;
        
        if (fallback && !tlsFallbackFound)
            additionalCount++;
        
        int[] offeredCipherSuites=clientState.getOfferedCipherSuites();
        if(additionalCount>0)
        {
        	offeredCipherSuites=new int[clientState.getOfferedCipherSuites().length + additionalCount];
        	System.arraycopy(clientState.getOfferedCipherSuites(), 0, offeredCipherSuites, 0, clientState.getOfferedCipherSuites().length);
        	if (noRenegExt && noRenegSCSV)
        		offeredCipherSuites[clientState.getOfferedCipherSuites().length]=CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV;        		
        	
        	if (fallback && !tlsFallbackFound)
        		offeredCipherSuites[offeredCipherSuites.length-1]=CipherSuite.TLS_FALLBACK_SCSV;
        }
        
        clientState.setOfferedCompressionMethods(new short[]{ CompressionMethod._null });
        
        byte[] session_id = DtlsHelper.EMPTY_BYTES;
        if (clientState.getTlsSession() != null)
        {
            session_id = clientState.getTlsSession().getSessionID();
            if (session_id == null || session_id.length > 32)
                session_id = DtlsHelper.EMPTY_BYTES;            
        }

        int totalLength = 8 + securityParameters.getClientRandom().length + session_id.length + 2*offeredCipherSuites.length + clientState.getOfferedCompressionMethods().length + DtlsHelper.calculateExtensionsLength(clientState.getClientExtensions());
        if(cookie!=null)
        	totalLength+=cookie.length+1;
        
        int capacity = DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + totalLength;
        ByteBuf data=Unpooled.buffer(capacity);
        short currSequence=sequence++;
        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.CLIENT_HELLO,data,totalLength);
        data.writeByte(client_version.getMajorVersion());
        data.writeByte(client_version.getMinorVersion());
        
        data.writeBytes(securityParameters.getClientRandom());

        // Session ID
        data.writeByte(session_id.length);
        data.writeBytes(session_id);
        
        //Cookie
        if(cookie!=null)
        {
        	data.writeByte(cookie.length);
            data.writeBytes(cookie);            
        }	
        else
        	data.writeBytes(DtlsHelper.EMPTY_BYTES_WITH_LENGTH);
        
        data.writeShort(2*offeredCipherSuites.length);
        for(int i=0;i<offeredCipherSuites.length;i++)
        	data.writeShort(offeredCipherSuites[i]);            
        
        data.writeByte(clientState.getOfferedCompressionMethods().length);
        for(int i=0;i<clientState.getOfferedCompressionMethods().length;i++)
        	data.writeByte(clientState.getOfferedCompressionMethods()[i]);
        
        // Extensions
        if (clientState.getClientExtensions() != null)
        	DtlsHelper.writeExtensions(data, clientState.getClientExtensions());
        
        recordLayer.setWriteVersion(ProtocolVersion.DTLSv10);
        recordLayer.send(currSequence, MessageType.CLIENT_HELLO, data);
        handshakeState=State.CLIENT_HELLO_SENT;
        
        if(handler!=null)
        	handler.handshakeStarted(remoteAddress, channel);
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void postProcessServerHelloDone() throws IOException
	{
		Vector clientSupplementalData = clientState.getClient().getClientSupplementalData();
        if (clientSupplementalData != null)
        {
        	int totalLength=3+DtlsHelper.calculateSupplementalDataLength(clientSupplementalData);
            ByteBuf supplementalDataOutput = Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + totalLength);
            short currSequence=sequence++;
            DtlsHelper.writeHandshakeHeader(currSequence,MessageType.SUPPLEMENTAL_DATA,supplementalDataOutput,totalLength);
            DtlsHelper.writeSupplementalData(supplementalDataOutput,clientSupplementalData);
            recordLayer.send(currSequence,MessageType.SUPPLEMENTAL_DATA,supplementalDataOutput);
        }

        if (clientState.getCertificateRequest() != null)
        {
            clientState.setClientCredentials(clientState.getAuthentication().getClientCredentials(clientState.getCertificateRequest()));
            Certificate clientCertificate = null;
            if (clientState.getClientCredentials() != null)
                clientCertificate = clientState.getClientCredentials().getCertificate();

            if (clientCertificate == null)
                clientCertificate = Certificate.EMPTY_CHAIN;
            
            short currSequence=sequence++;
            ByteBuf certificateOutput = DtlsHelper.writeCertificate(currSequence,clientCertificate);
            recordLayer.send(currSequence,MessageType.CERTIFICATE,certificateOutput);
        }

        if (clientState.getClientCredentials() != null)
        	clientState.getKeyExchange().processClientCredentials(clientState.getClientCredentials());
        else
        	clientState.getKeyExchange().skipClientCredentials();
        
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        clientState.getKeyExchange().generateClientKeyExchange(buf);        
        byte[] clientKeyExchange = buf.toByteArray();
        ByteBuf keyExchangeOutput=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + clientKeyExchange.length);
        short currSequence=sequence++;
        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.CLIENT_KEY_EXCHANGE,keyExchangeOutput,clientKeyExchange.length);
        keyExchangeOutput.writeBytes(clientKeyExchange);
        recordLayer.send(currSequence,MessageType.CLIENT_KEY_EXCHANGE, keyExchangeOutput);
        
        TlsHandshakeHash prepareFinishHash = clientState.getHandshakeHash();
        clientState.setHandshakeHash(clientState.getHandshakeHash().stopTracking());
        
		clientState.getClientContext().getSecurityParameters().setSessionHash(DtlsHelper.getCurrentPRFHash(clientState.getClientContext(), prepareFinishHash, null));
        
        DtlsHelper.establishMasterSecret(clientState.getClientContext().getSecurityParameters(), clientState.getClientContext(), clientState.getKeyExchange());
        recordLayer.initPendingEpoch(clientState.getClient().getCipher());

        if (clientState.getClientCredentials() != null && clientState.getClientCredentials() instanceof TlsSignerCredentials)
        {
            TlsSignerCredentials signerCredentials = (TlsSignerCredentials)clientState.getClientCredentials();

            SignatureAndHashAlgorithm signatureAndHashAlgorithm = DtlsHelper.getSignatureAndHashAlgorithm(clientState.getClientContext(), signerCredentials);

            byte[] hash;
            if (signatureAndHashAlgorithm == null)
                hash = clientState.getClientContext().getSecurityParameters().getSessionHash();                
            else
            	hash = prepareFinishHash.getFinalHash(signatureAndHashAlgorithm.getHash());
                  
            byte[] signature = signerCredentials.generateCertificateSignature(hash);
            int addon=0;
            if (signatureAndHashAlgorithm != null)
            	addon=2;
            
            ByteBuf certificateVerifyBody=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + addon + 2 + signature.length);
            currSequence=sequence++;
            DtlsHelper.writeHandshakeHeader(currSequence,MessageType.CERTIFICATE_VERIFY,certificateVerifyBody,addon + 2 + signature.length);
            if (signatureAndHashAlgorithm != null)
            {
            	certificateVerifyBody.writeByte(signatureAndHashAlgorithm.getHash());
            	certificateVerifyBody.writeByte(signatureAndHashAlgorithm.getSignature());            	
            }
            
            certificateVerifyBody.writeShort(signature.length);
            certificateVerifyBody.writeBytes(signature);            
            recordLayer.send(currSequence,MessageType.CERTIFICATE_VERIFY, certificateVerifyBody);            
        }

        byte[] clientVerifyData = DtlsHelper.calculateVerifyData(clientState.getClientContext(), ExporterLabel.client_finished, DtlsHelper.getCurrentPRFHash(clientState.getClientContext(), clientState.getHandshakeHash(), null));
        ByteBuf serverVerifyBuffer=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + clientVerifyData.length);
        currSequence=sequence++;
        DtlsHelper.writeHandshakeHeader(currSequence,MessageType.FINISHED,serverVerifyBuffer,clientVerifyData.length);
        serverVerifyBuffer.writeBytes(clientVerifyData);
        recordLayer.send(currSequence,MessageType.FINISHED, serverVerifyBuffer);
	}
	
	public void postProcessFinished() throws IOException
	{
		if(handshakeState==State.SERVER_HELLO_RECEIVED)
		{
			 byte[] clientVerifyData = DtlsHelper.calculateVerifyData(clientState.getClientContext(), ExporterLabel.client_finished, DtlsHelper.getCurrentPRFHash(clientState.getClientContext(), clientState.getHandshakeHash(), null));
			 ByteBuf serverVerifyBuffer=Unpooled.buffer(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH + clientVerifyData.length);
			 short currSequence=sequence++;
			 DtlsHelper.writeHandshakeHeader(currSequence,MessageType.FINISHED,serverVerifyBuffer,clientVerifyData.length);
			 serverVerifyBuffer.writeBytes(clientVerifyData);
			 recordLayer.send(currSequence,MessageType.FINISHED, serverVerifyBuffer);
			 
			 if(handler!=null)
		        	handler.handshakeCompleted(remoteAddress, channel);
		}

		recordLayer.handshakeSuccessful();
        
		if(handshakeState==State.SERVER_HELLO_RECEIVED)
        	clientState.getClientContext().setResumableSession(clientState.getTlsSession());
        else
        {
	        if (clientState.getTlsSession() != null)
	        {
	            clientState.setSessionParameters(new SessionParameters.Builder()
	                .setCipherSuite(clientState.getClientContext().getSecurityParameters().getCipherSuite())
	                .setCompressionAlgorithm(clientState.getClientContext().getSecurityParameters().getCompressionAlgorithm())
	                .setMasterSecret(clientState.getClientContext().getSecurityParameters().getMasterSecret())
	                .setPeerCertificate(serverCertificate)
	                .setPSKIdentity(clientState.getClientContext().getSecurityParameters().getPSKIdentity())
	                .setSRPIdentity(clientState.getClientContext().getSecurityParameters().getSRPIdentity())
	                .setServerExtensions(clientState.getServerExtensions())
	                .build());
	
	            clientState.setTlsSession(new AsyncDtlsSessionImpl(clientState.getTlsSession().getSessionID(), clientState.getSessionParameters()));
	            clientState.getClientContext().setResumableSession(clientState.getTlsSession());
	        }
        }
        
        clientState.getClient().notifyHandshakeComplete(); 
	}
	
	@Override
	public void handleHandshake(MessageType messageType, ByteBuf data) throws IOException 
	{
		if(parentHandler!=null)
			parentHandler.handleHandshake(messageType, data);
		
		switch(messageType)
		{
			case HELLO_VERIFY_REQUEST:
				if(handshakeState!=State.CLIENT_HELLO_SENT)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processHelloVerifyRequest(data);
				break;
			case SERVER_HELLO:
				if(handshakeState!=State.CLIENT_HELLO_SENT)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processServerHello(data);
				clientState.setHandshakeHash(clientState.getHandshakeHash().notifyPRFDetermined());
				
				short maxFragmentLength=clientState.getClientContext().getSecurityParameters().getMaxFragmentLength();
		        if (maxFragmentLength >= 0)
		        {
		            if (!MaxFragmentLength.isValid(maxFragmentLength))
		                throw new TlsFatalAlert(AlertDescription.internal_error); 
		            
		            int plainTextLimit = 1 << (8 + maxFragmentLength);
		            recordLayer.setPlaintextLimit(plainTextLimit);
		        }
		        
		        if (clientState.isResumedSession())
		        {
		        	byte[] masterSecret=new byte[clientState.getSessionParameters().getMasterSecret().length];
		        	System.arraycopy(clientState.getSessionParameters().getMasterSecret(), 0, masterSecret, 0, masterSecret.length);
		            clientState.getClientContext().getSecurityParameters().setMasterSecret(masterSecret);
		            recordLayer.initPendingEpoch(clientState.getClient().getCipher());
		        }
		        else
		        {
		        	if (clientState.getSessionParameters() != null)
		            {
		        		clientState.getSessionParameters().clear();
		        		clientState.setSessionParameters(null);
		            }

		            if (clientState.getTlsSession() != null)
		            {
		            	clientState.getTlsSession().invalidate();
		            	clientState.setTlsSession(null);
		            }
		            
		            if (clientState.getSelectedSessionID().length > 0)
		                clientState.setTlsSession(new AsyncDtlsSessionImpl(clientState.getSelectedSessionID(), null));
		        }
		        handshakeState=State.SERVER_HELLO_RECEIVED;
				break;
			case SUPPLEMENTAL_DATA:
				if(handshakeState!=State.SERVER_HELLO_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processServerSupplementalData(data);
				handshakeState=State.SUPP_DATA_RECEIVED;
				break;
			case CERTIFICATE:
				if(handshakeState==State.SERVER_HELLO_RECEIVED)
				{
					clientState.getClient().processServerSupplementalData(null);
					handshakeState = State.SUPP_DATA_RECEIVED;
				}
				
				if(handshakeState!=State.SUPP_DATA_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				clientState.setKeyExchange(clientState.getClient().getKeyExchange());
				clientState.getKeyExchange().init(clientState.getClientContext());

				processServerCertificate(data);
				handshakeState=State.CERTIFICATE_RECEIVED;
				break;
			case CERTIFICATE_STATUS:
				if(handshakeState==State.SERVER_HELLO_RECEIVED)
				{
					clientState.getClient().processServerSupplementalData(null);
					handshakeState = State.SUPP_DATA_RECEIVED;
				}
				
				if(handshakeState==State.SUPP_DATA_RECEIVED)
				{
					clientState.setKeyExchange(clientState.getClient().getKeyExchange());
					clientState.getKeyExchange().init(clientState.getClientContext());
					clientState.getKeyExchange().skipServerCredentials();
					handshakeState = State.CERTIFICATE_RECEIVED;
				}
				
				if(handshakeState!=State.CERTIFICATE_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processCertificateStatus(data);
				handshakeState=State.CERTIFICATE_STATUS_RECEIVED;				
				break;
			case SERVER_KEY_EXCHANGE:
				if(handshakeState==State.SERVER_HELLO_RECEIVED)
				{
					clientState.getClient().processServerSupplementalData(null);
					handshakeState = State.SUPP_DATA_RECEIVED;
				}
				
				if(handshakeState==State.SUPP_DATA_RECEIVED)
				{
					clientState.setKeyExchange(clientState.getClient().getKeyExchange());
					clientState.getKeyExchange().init(clientState.getClientContext());
					clientState.getKeyExchange().skipServerCredentials();
					handshakeState = State.CERTIFICATE_RECEIVED;
				}
				
				if(handshakeState == State.CERTIFICATE_RECEIVED)
					handshakeState=State.CERTIFICATE_STATUS_RECEIVED;				
				
				if(handshakeState!=State.CERTIFICATE_STATUS_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processServerKeyExchange(data);
				handshakeState=State.SERVER_KEY_EXCHANGE_RECEIVED;
				break;
			case CERTIFICATE_REQUEST:
				if(handshakeState==State.SERVER_HELLO_RECEIVED)
				{
					clientState.getClient().processServerSupplementalData(null);
					handshakeState = State.SUPP_DATA_RECEIVED;
				}
				
				if(handshakeState==State.SUPP_DATA_RECEIVED)
				{
					clientState.setKeyExchange(clientState.getClient().getKeyExchange());
					clientState.getKeyExchange().init(clientState.getClientContext());
					clientState.getKeyExchange().skipServerCredentials();
					handshakeState = State.CERTIFICATE_RECEIVED;
				}
				
				if(handshakeState == State.CERTIFICATE_RECEIVED)
					handshakeState=State.CERTIFICATE_STATUS_RECEIVED;				
				
				if(handshakeState == State.CERTIFICATE_STATUS_RECEIVED)
				{
					clientState.getKeyExchange().skipServerKeyExchange();
					handshakeState=State.SERVER_KEY_EXCHANGE_RECEIVED;					
				}
				
				if(handshakeState!=State.SERVER_KEY_EXCHANGE_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processCertificateRequest(data);
				handshakeState=State.CERTIFICATE_REQUEST_RECEIVED;				
				break;
			case SERVER_HELLO_DONE:
				if(handshakeState==State.SERVER_HELLO_RECEIVED)
				{
					clientState.getClient().processServerSupplementalData(null);
					handshakeState = State.SUPP_DATA_RECEIVED;
				}
				
				if(handshakeState==State.SUPP_DATA_RECEIVED)
				{
					clientState.setKeyExchange(clientState.getClient().getKeyExchange());
					clientState.getKeyExchange().init(clientState.getClientContext());
					clientState.getKeyExchange().skipServerCredentials();
					handshakeState = State.CERTIFICATE_RECEIVED;
				}
				
				if(handshakeState == State.CERTIFICATE_RECEIVED)
					handshakeState=State.CERTIFICATE_STATUS_RECEIVED;				
				
				if(handshakeState == State.CERTIFICATE_STATUS_RECEIVED)
				{
					clientState.getKeyExchange().skipServerKeyExchange();
					handshakeState=State.SERVER_KEY_EXCHANGE_RECEIVED;					
				}
				
				if(handshakeState == State.SERVER_KEY_EXCHANGE_RECEIVED)
					handshakeState=State.CERTIFICATE_REQUEST_RECEIVED;				
				
				if(handshakeState!=State.CERTIFICATE_REQUEST_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processServerHelloDone(data);
				handshakeState=State.SERVER_HELLO_DONE;
				break;
			case SESSION_TICKET:
				if(handshakeState!=State.FINISH_SENT || !clientState.isExpectSessionTicket())
					throw new TlsFatalAlert(AlertDescription.unexpected_message);
				
				processNewSessionTicket(data);
				handshakeState=State.SESSION_TICKET_RECEIVED;				
				break;
			case FINISHED:
				if(handshakeState!=State.FINISH_SENT && handshakeState!=State.SESSION_TICKET_RECEIVED && handshakeState!=State.SERVER_HELLO_RECEIVED)
					throw new TlsFatalAlert(AlertDescription.unexpected_message);

				if(handshakeState==State.FINISH_SENT && clientState.isExpectSessionTicket())
					throw new TlsFatalAlert(AlertDescription.unexpected_message);

				if(handshakeState==State.SERVER_HELLO_RECEIVED && clientState.isResumedSession())
					throw new TlsFatalAlert(AlertDescription.unexpected_message);

				processFinished(data);
				break;
			default:
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
		}	
	}

	@Override
	public void postProcessHandshake(MessageType messageType, ByteBuf data) throws IOException 
	{
		//not throwing exception since already handled in handleHandshake
		if(parentHandler!=null)
			parentHandler.postProcessHandshake(messageType, data);
		
		switch(messageType)
		{
			case SERVER_HELLO_DONE:
				postProcessServerHelloDone();
				handshakeState=State.FINISH_SENT;
				break;
			case FINISHED:
				postProcessFinished();
				break;
			default:
				break;
		}
	}
		
	private void processHelloVerifyRequest(ByteBuf body) throws IOException
	{
		 ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
         ProtocolVersion client_version = clientState.getClientContext().getClientVersion();

         if (!recordLayerVersion.isEqualOrEarlierVersionOf(client_version))
             throw new TlsFatalAlert(AlertDescription.illegal_parameter);
         
         recordLayer.setReadVersion(null);

         ProtocolVersion server_version = ProtocolVersion.get(body.readByte() & 0xFF, body.readByte() & 0xFF);
         byte[] cookie = new byte[body.readByte()];
         body.readBytes(cookie);
         
         if (!server_version.isEqualOrEarlierVersionOf(clientState.getClientContext().getClientVersion()))
             throw new TlsFatalAlert(AlertDescription.illegal_parameter);
         
         if (!ProtocolVersion.DTLSv12.isEqualOrEarlierVersionOf(server_version) && cookie.length > 32)
             throw new TlsFatalAlert(AlertDescription.illegal_parameter);
         
         clientState.getHandshakeHash().reset();
         initHandshake(cookie);         
	}
	
	@SuppressWarnings("unchecked")
	private void processServerHello(ByteBuf body) throws IOException
	{
		ProtocolVersion recordLayerVersion = recordLayer.getReadVersion();
        reportServerVersion(recordLayerVersion);
        recordLayer.setWriteVersion(recordLayerVersion);
        
        AsyncDtlsSecurityParameters securityParameters = clientState.getClientContext().getSecurityParameters();

        ProtocolVersion server_version = ProtocolVersion.get(body.readByte() & 0xFF, body.readByte() & 0xFF);
        reportServerVersion(server_version);
        
        byte[] serverRandom=new byte[32];
        body.readBytes(serverRandom);
        securityParameters.setServerRandom(serverRandom);

        byte[] selectedSessionID=new byte[body.readUnsignedByte()];
        if(selectedSessionID.length>0)
        	body.readBytes(selectedSessionID);
        
        clientState.setSelectedSessionID(selectedSessionID);
        if (selectedSessionID.length > 32)
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);

        clientState.getClient().notifySessionID(selectedSessionID);        
        clientState.setResumedSession(selectedSessionID.length > 0 && clientState.getTlsSession() != null && Arrays.equals(clientState.getSelectedSessionID(), clientState.getTlsSession().getSessionID()));

        int selectedCipherSuite = body.readUnsignedShort();
        Boolean inOfferedCipherSuites=false;
        for(int i=0;i<clientState.getOfferedCipherSuites().length;i++)
        {
        	if(selectedCipherSuite==clientState.getOfferedCipherSuites()[i])
        	{
        		inOfferedCipherSuites=true;
        		break;
        	}
        }
                
        if (!inOfferedCipherSuites || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL || CipherSuite.isSCSV(selectedCipherSuite) || !DtlsHelper.getMinimumVersion(selectedCipherSuite).isEqualOrEarlierVersionOf(clientState.getClientContext().getServerVersion().getEquivalentTLSVersion()))
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        
        switch (DtlsHelper.getEncryptionAlgorithm(selectedCipherSuite))
        {
        	case EncryptionAlgorithm.RC4_40:
        	case EncryptionAlgorithm.RC4_128:
        		throw new TlsFatalAlert(AlertDescription.internal_error);
        }
        
        clientState.getClient().notifySelectedCipherSuite(selectedCipherSuite);

        short selectedCompressionMethod = body.readUnsignedByte();
        Boolean inOfferedCompressionMethods=false;
        for(int i=0;i<clientState.getOfferedCompressionMethods().length;i++)
        {
        	if(selectedCompressionMethod==clientState.getOfferedCompressionMethods()[i])
        	{
        		inOfferedCompressionMethods=true;
        		break;
        	}
        }
        
        if (!inOfferedCompressionMethods)
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);

        clientState.getClient().notifySelectedCompressionMethod(selectedCompressionMethod);
        clientState.setServerExtensions(DtlsHelper.readSelectedExtensions(body));

        if (clientState.getServerExtensions() != null)
        {
            Enumeration<Integer> e = clientState.getServerExtensions().keys();
            while (e.hasMoreElements())
            {
                Integer extType = (Integer)e.nextElement();
                if (extType.equals(DtlsHelper.EXT_RenegotiationInfo))
                    continue;
                
                if (clientState.getClientExtensions().get(extType) == null)
                    throw new TlsFatalAlert(AlertDescription.unsupported_extension);                               
            }
        }
        
        byte[] renegExtData = clientState.getServerExtensions().get(DtlsHelper.EXT_RenegotiationInfo);
        if (renegExtData != null)
        {
            clientState.setSecure_renegotiation(true);
            
            if (!Arrays.equals(renegExtData,DtlsHelper.EMPTY_BYTES_WITH_LENGTH))
                throw new TlsFatalAlert(AlertDescription.handshake_failure);            
        }

        if(clientState.isSecure_renegotiation())
        	clientState.getClient().notifySecureRenegotiation(clientState.isSecure_renegotiation());
        
        Hashtable<Integer,byte[]> sessionClientExtensions = clientState.getClientExtensions();
        Hashtable<Integer,byte[]> sessionServerExtensions = clientState.getServerExtensions();
        if (clientState.isResumedSession())
        {
            if (selectedCipherSuite != clientState.getSessionParameters().getCipherSuite() || selectedCompressionMethod != clientState.getSessionParameters().getCompressionAlgorithm())
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            sessionClientExtensions = null;
            sessionServerExtensions = clientState.getSessionParameters().readServerExtensions();
        }

        securityParameters.setCipherSuite(selectedCipherSuite);
        securityParameters.setCompressionAlgorithm(selectedCompressionMethod);

        if (sessionServerExtensions != null)
        {
        	byte[] encryptThenMac=sessionServerExtensions.get(DtlsHelper.EXT_encrypt_then_mac);
        	if(encryptThenMac!=null && encryptThenMac.length>0)
        		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        	
        	boolean serverSentEncryptThenMAC = encryptThenMac!=null;        	
            if (serverSentEncryptThenMAC && DtlsHelper.getCipherType(securityParameters.getCipherSuite())!=CipherType.block)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            
            securityParameters.setEncryptThenMAC(serverSentEncryptThenMAC);
            
            byte[] extendedMacSecret=sessionServerExtensions.get(DtlsHelper.EXT_extended_master_secret);
        	if(extendedMacSecret!=null && extendedMacSecret.length>0)
        		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        	
        	securityParameters.setExtendedMasterSecret(extendedMacSecret!=null);
            
        	securityParameters.setMaxFragmentLength(DtlsHelper.evaluateMaxFragmentLengthExtension(clientState.isResumedSession(),sessionClientExtensions, sessionServerExtensions, AlertDescription.illegal_parameter));
            
            byte[] truncatedHMAC=sessionServerExtensions.get(DtlsHelper.EXT_truncated_hmac);
        	if(truncatedHMAC!=null && truncatedHMAC.length>0)
        		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        	
        	securityParameters.setTruncatedHMac(truncatedHMAC!=null);

        	byte[] statusRequest=sessionServerExtensions.get(DtlsHelper.EXT_status_request);
        	if(statusRequest!=null && statusRequest.length>0)
        		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        	
        	clientState.setAllowCertificateStatus(!clientState.isResumedSession() && statusRequest!=null);

        	byte[] sessionTicket=sessionServerExtensions.get(DtlsHelper.EXT_SessionTicket);
        	if(sessionTicket!=null && sessionTicket.length>0)
        		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        	
        	clientState.setExpectSessionTicket(!clientState.isResumedSession() && sessionTicket!=null);
        }

        if (sessionClientExtensions != null)
            clientState.getClient().processServerExtensions(sessionServerExtensions);
        
        securityParameters.setPrfAlgorithm(DtlsHelper.getPRFAlgorithm(clientState.getClientContext().getServerVersion(),securityParameters.getCipherSuite()));
        securityParameters.setVerifyDataLength(12);
	}
	
	private void processServerSupplementalData(ByteBuf body) throws IOException
	{
		Vector<SupplementalDataEntry> serverSupplementalData = DtlsHelper.readSupplementalData(body);
        clientState.getClient().processServerSupplementalData(serverSupplementalData);
	}
	
	private void processServerCertificate(ByteBuf data) throws IOException
	{
		serverCertificate = DtlsHelper.parseCertificate(data);
		clientState.getKeyExchange().processServerCertificate(serverCertificate);
		clientState.setAuthentication(clientState.getClient().getAuthentication());
		clientState.getAuthentication().notifyServerCertificate(serverCertificate);        
	}
	
	private void processCertificateStatus(ByteBuf data) throws IOException
	{
		if (!clientState.isAllowCertificateStatus())
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        
        clientState.setCertificateStatus(DtlsHelper.parseCertificateStatus(data));
	}
	
	private void processServerKeyExchange(ByteBuf body) throws IOException
	{	
		//can not parse with byte buffer , needs input stream
		byte[] backedData=new byte[body.readableBytes()];
		body.readBytes(backedData);
		ByteArrayInputStream buf = new ByteArrayInputStream(backedData);
        clientState.getKeyExchange().processServerKeyExchange(buf);        
	}
	
	private void processCertificateRequest(ByteBuf body) throws IOException
	{
		if (clientState.getAuthentication() == null)
			throw new TlsFatalAlert(AlertDescription.handshake_failure);
	     
		clientState.setCertificateRequest(AsyncCertificateRequest.parse(clientState.getClientContext().getServerVersion(), body));
		
		clientState.getKeyExchange().validateCertificateRequest(clientState.getCertificateRequest());
		if (clientState.getCertificateRequest().getSupportedSignatureAlgorithms() != null)
        {
            for (int i = 0; i < clientState.getCertificateRequest().getSupportedSignatureAlgorithms().size(); ++i)
            {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm)clientState.getCertificateRequest().getSupportedSignatureAlgorithms().elementAt(i);
                short hashAlgorithm = signatureAndHashAlgorithm.getHash();
                if (!HashAlgorithm.isPrivate(hashAlgorithm))
                	clientState.getHandshakeHash().trackHashAlgorithm(hashAlgorithm);                	                 
            }
        }
	}
	
	private void processServerHelloDone(ByteBuf body) throws IOException
	{
		if (body.readableBytes() != 0)
            throw new TlsFatalAlert(AlertDescription.decode_error);
        
		clientState.getHandshakeHash().sealHashAlgorithms();
	}
	
	private void processNewSessionTicket(ByteBuf body) throws IOException
	{
		long ticketLifetimeHint = body.readUnsignedInt();
        byte[] ticket = new byte[body.readUnsignedShort()];
        body.readBytes(body);
        NewSessionTicket newSessionTicket = new NewSessionTicket(ticketLifetimeHint, ticket);
        clientState.getClient().notifyNewSessionTicket(newSessionTicket);
	}
	
	private void processFinished(ByteBuf body) throws IOException
	{
		byte[] expectedClientVerifyData = DtlsHelper.calculateVerifyData(clientState.getClientContext(), ExporterLabel.server_finished,DtlsHelper.getCurrentPRFHash(clientState.getClientContext(), clientState.getHandshakeHash(), null));
        if(body.readableBytes()!=expectedClientVerifyData.length)
			throw new TlsFatalAlert(AlertDescription.handshake_failure);
		
		byte[] serverVerifyData=new byte[body.readableBytes()];
		body.readBytes(serverVerifyData);
		
		if(!Arrays.equals(serverVerifyData, expectedClientVerifyData))
			throw new TlsFatalAlert(AlertDescription.handshake_failure);					               
	}
	
	private void reportServerVersion(ProtocolVersion server_version) throws IOException
	{
		ProtocolVersion currentServerVersion = clientState.getClientContext().getServerVersion();
		if (null == currentServerVersion)
		{
			clientState.getClientContext().setServerVersion(server_version);
			clientState.getClient().notifyServerVersion(server_version);
		}
		else if (!currentServerVersion.equals(server_version))
			throw new TlsFatalAlert(AlertDescription.illegal_parameter);		
	}
}