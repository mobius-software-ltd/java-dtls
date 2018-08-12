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
import io.netty.channel.socket.DatagramPacket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.ChangeCipherSpec;
import org.bouncycastle.crypto.tls.ContentType;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsCipher;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;
import org.bouncycastle.crypto.tls.TlsNullCipher;
import org.bouncycastle.crypto.tls.TlsPeer;

public class AsyncDtlsRecordLayer 
{
	public static final int RECORD_HEADER_LENGTH = 13;
	public static final int MAX_FRAGMENT_LENGTH = 1 << 11;
	public static final long TCP_MSL = 1000L * 60 * 2;
	public static final long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

    private final TlsPeer peer;
    
    private volatile boolean closed = false;
    private volatile boolean failed = false;
    private volatile ProtocolVersion readVersion = null, writeVersion = null;
    private volatile boolean inHandshake;
    private volatile int plaintextLimit;
    private AsyncDtlsEpoch currentEpoch, pendingEpoch;
    private AsyncDtlsEpoch readEpoch, writeEpoch;
    
    private Channel channel;
    private InetSocketAddress remoteAddress;
    
    private HandshakeHandler handshakeHandler;
    private TlsHandshakeHash handshakeHash;
    
    private ConcurrentHashMap<Short, PendingMessageData> pendingBuffers=new ConcurrentHashMap<Short,PendingMessageData>();
    
    public AsyncDtlsRecordLayer(TlsHandshakeHash handshakeHash,HandshakeHandler handshakeHandler,Channel channel,TlsContext context, TlsPeer peer,InetSocketAddress remoteAddress)
    {
    	this.handshakeHash=handshakeHash;
    	this.channel=channel;
    	this.remoteAddress=remoteAddress;
    	this.handshakeHandler=handshakeHandler;
    	this.peer = peer;
        this.inHandshake = true;
        this.currentEpoch = new AsyncDtlsEpoch(0, new TlsNullCipher(context));
        this.pendingEpoch = null;
        this.readEpoch = currentEpoch;
        this.writeEpoch = currentEpoch;

        setPlaintextLimit(MAX_FRAGMENT_LENGTH);
    }
    
    public void setPlaintextLimit(int plaintextLimit)
    {
        this.plaintextLimit = plaintextLimit;
    }

    public int getReadEpoch()
    {
        return readEpoch.getEpoch();
    }

    public ProtocolVersion getReadVersion()
    {
        return readVersion;
    }

    public void setReadVersion(ProtocolVersion readVersion)
    {
        this.readVersion = readVersion;
    }

    public void setWriteVersion(ProtocolVersion writeVersion)
    {
        this.writeVersion = writeVersion;
    }

    void initPendingEpoch(TlsCipher pendingCipher)
    {
        if (pendingEpoch != null)
            throw new IllegalStateException();
        
        this.pendingEpoch = new AsyncDtlsEpoch(writeEpoch.getEpoch() + 1, pendingCipher);
    }
    
    public void handshakeSuccessful()
    {
        if (readEpoch == currentEpoch || writeEpoch == currentEpoch)
            throw new IllegalStateException();
        
        this.inHandshake = false;
        this.currentEpoch = pendingEpoch;
        this.pendingEpoch = null;
    }

    public int getReceiveLimit()
    {
    	return this.plaintextLimit;
    }

    public int getSendLimit()
    {
    	return this.plaintextLimit-RECORD_HEADER_LENGTH;
    }
    
    public List<ByteBuf> receive(ByteBuf record) throws IOException
    {
    	List<ByteBuf> outputList=new ArrayList<ByteBuf>();
    	while(record.readableBytes()>RECORD_HEADER_LENGTH)
    	{
    		short type = (short)(record.readByte() & 0x00FF);
	    	ProtocolVersion version=ProtocolVersion.get(record.readByte() & 0xFF, record.readByte() & 0xFF);
	    	int epoch = record.readUnsignedShort();
	        long seq = DtlsHelper.readUint48(record);
	        //just reading length,not using it
	        record.readShort();
	        
	        byte[] realData=new byte[record.readableBytes()];
	        record.readBytes(realData);
	        
	        AsyncDtlsEpoch recordEpoch = null;
	        if (epoch == readEpoch.getEpoch())
	            recordEpoch = readEpoch;

	        if (recordEpoch == null)
	            continue;
	
	        if (recordEpoch.getReplayWindow().shouldDiscard(seq))
	        	continue;
	
	        if (!version.isDTLS())
	        	continue;
	
	        if (readVersion != null && !readVersion.equals(version))
	        	continue;
	        
	        byte[] plaintext = recordEpoch.getCipher().decodeCiphertext(getMacSequenceNumber(recordEpoch.getEpoch(), seq), type, realData, 0, realData.length);
	        ByteBuf output=Unpooled.wrappedBuffer(plaintext);
	        
	        recordEpoch.getReplayWindow().reportAuthenticated(seq);
	        if (plaintext.length > this.plaintextLimit)
	        	continue;
	
	        if (readVersion == null)
	            readVersion = version;
	        
	        switch (type)
	        {
		        case ContentType.alert:
		            if (output.readableBytes() == 2)
		            {
		                short alertLevel = (short)(output.readByte() & 0x0FF);
		                short alertDescription = (short)(output.readByte() & 0x0FF);
		
		                peer.notifyAlertReceived(alertLevel, alertDescription);
		
		                if (alertLevel == AlertLevel.fatal)
		                {
		                    failed();
		                    throw new TlsFatalAlert(alertDescription);
		                }
		
		                if (alertDescription == AlertDescription.close_notify)
		                    closeTransport();	                
		            }
		
		            continue;
		        case ContentType.application_data:
		            if (inHandshake)
		            	continue;
		            break;
		        case ContentType.change_cipher_spec:
		        	while(output.readableBytes()>0)
		            {
		            	
		                short message = (short)(output.readByte() & 0x0FF);
		                if (message != ChangeCipherSpec.change_cipher_spec)
		                	continue;
		            
		                if (pendingEpoch != null)
		                    readEpoch = pendingEpoch;	                
		            }
		
		        	continue;
		        case ContentType.handshake:
		            if (!inHandshake)
		                continue;
		            
		            HandshakeHeader handshakeHeader=DtlsHelper.readHandshakeHeader(output);
		            
		            if(handshakeHeader!=null)
		            {
		            	if(!handshakeHeader.getFragmentLength().equals(handshakeHeader.getTotalLength()))
		            	{
		            		PendingMessageData data=pendingBuffers.get(handshakeHeader.getMessageSequence());
		            		if(data==null)
		            		{
		            			data=new PendingMessageData(Unpooled.buffer(handshakeHeader.getTotalLength()));
		            			pendingBuffers.put(handshakeHeader.getMessageSequence(),data);
		            		}
		            			
		            		data.writeBytes(output, handshakeHeader.getFragmentOffset());
		            		if(data.getWrottenBytes().equals(handshakeHeader.getTotalLength()))
		            		{
		            			data.getBuffer().writerIndex(handshakeHeader.getTotalLength());
		            			byte[] packetData=null;
		            			if (handshakeHeader.getMessageType() != MessageType.HELLO_REQUEST)
		            	        {
		            				ByteBuf copy=data.getBuffer().copy();
			            			packetData=new byte[copy.readableBytes()];
			            			copy.readBytes(packetData);	            		
		            	        }
		            			
		            			if(handshakeHeader.getMessageType()!=null && handshakeHandler!=null)
		            				handshakeHandler.handleHandshake(handshakeHeader.getMessageType(), data.getBuffer());
		            			
		            			if (handshakeHeader.getMessageType() != MessageType.HELLO_REQUEST)
			            	    {
		            				byte[] pseudoHeader=new byte[DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH];
		            				ByteBuf headerBuffer=Unpooled.wrappedBuffer(pseudoHeader);
		            				headerBuffer.writerIndex(0);
		            				DtlsHelper.writeHandshakeHeader(handshakeHeader.getMessageSequence(), handshakeHeader.getMessageType(), headerBuffer, handshakeHeader.getTotalLength());
		            				headerBuffer.readerIndex(0);
		            				handshakeHash.update(pseudoHeader, 0, pseudoHeader.length); 
			            			handshakeHash.update(packetData, 0, packetData.length); 
		            	        }
		            			
		            			if(handshakeHeader.getMessageType()!=null && handshakeHandler!=null)
		            				handshakeHandler.postProcessHandshake(handshakeHeader.getMessageType(), data.getBuffer());
		            			
		            			pendingBuffers.remove(handshakeHeader.getMessageSequence());
		            		}		            				            		
		            	}
		            	else
		            	{
		            		byte[] packetData=null;
	            			if (handshakeHeader.getMessageType() != MessageType.HELLO_REQUEST)
	            	        {
		            			ByteBuf copy=output.copy();
		            			packetData=new byte[copy.readableBytes()];
		            			copy.readBytes(packetData);	            		
	            	        }
	            			
	            			if(handshakeHeader.getMessageType()!=null && handshakeHandler!=null)
	            				handshakeHandler.handleHandshake(handshakeHeader.getMessageType(), output);
	            			
	            			if (handshakeHeader.getMessageType() != MessageType.HELLO_REQUEST)
		            	    {
		            			byte[] pseudoHeader=new byte[DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH];
		            			ByteBuf headerBuffer=Unpooled.wrappedBuffer(pseudoHeader);
	            				headerBuffer.writerIndex(0);
	            				DtlsHelper.writeHandshakeHeader(handshakeHeader.getMessageSequence(), handshakeHeader.getMessageType(), headerBuffer, handshakeHeader.getTotalLength());
	            				headerBuffer.readerIndex(0);
	            				handshakeHash.update(pseudoHeader, 0, pseudoHeader.length); 
		            			handshakeHash.update(packetData, 0, packetData.length); 
	            	        }
		            		
	            			if(handshakeHeader.getMessageType()!=null && handshakeHandler!=null)
	            				handshakeHandler.postProcessHandshake(handshakeHeader.getMessageType(), output);	            		
		            	}
		            }
		            
		            continue;
		        case ContentType.heartbeat:
		        	continue;	       
	        }
	        
	        outputList.add(output);
    	}
    	
        return outputList;
    }
    
    public void sendAlert(short alertLevel, short alertDescription, String message, Throwable cause) throws IOException
    {
    	if(closed)
    		return;
    	
    	peer.notifyAlertRaised(alertLevel, alertDescription, message, cause);
    	ByteBuf buf=Unpooled.buffer(2);
    	buf.writeByte(alertLevel);
    	buf.writeByte(alertDescription);
    	sendRecord(ContentType.alert, buf);
    }
    
    public void send(ByteBuf buffer) throws IOException
    {
    	if(closed)
    		return;
    	
    	if(this.inHandshake)
    		return;
    	
    	sendRecord(ContentType.application_data,buffer);    	
    }
    
    public void send(short sequence,MessageType messageType,ByteBuf buffer) throws IOException
    {
    	if(closed)
    		return;
    	
    	if (messageType == MessageType.FINISHED)
        {
            AsyncDtlsEpoch nextEpoch = null;
            if (this.inHandshake)
                nextEpoch = pendingEpoch;
            
            if (nextEpoch == null)
                throw new IllegalStateException();
            
            ByteBuf cipherSpecBuf=Unpooled.buffer(1);
            cipherSpecBuf.writeByte(1);
            sendRecord(ContentType.change_cipher_spec, cipherSpecBuf);

            writeEpoch = nextEpoch;
        }
        
    	ByteBuf copy=buffer.copy();
    	byte[] realArray=new byte[copy.readableBytes()];
    	copy.readBytes(realArray);

    	if(buffer.readableBytes()<=getSendLimit())
    		sendRecord(ContentType.handshake, buffer);
    	else
    	{
    		int fragmentOffset=0;
    		int totalLength=buffer.readableBytes()-DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH;
    		
    		ByteBuf header=buffer.readBytes(DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH);
			header.release();
			
			do
    	    {
				int fragmentLength = Math.min(buffer.readableBytes()+DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH, getSendLimit());    			
    			ByteBuf current=Unpooled.buffer(fragmentLength);
    			DtlsHelper.writeHandshakeHeader(fragmentOffset, fragmentLength-DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH, sequence, messageType, current, totalLength);
    			buffer.readBytes(current, fragmentLength-DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH);
    			sendRecord(ContentType.handshake,current);
    			fragmentOffset+=fragmentLength-DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH;     			
    	    }
    		while (buffer.readableBytes()>0);    	            			    	    
    	}
    	
    	handshakeHash.update(realArray, 0, DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH);
    	handshakeHash.update(realArray, DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH, realArray.length-DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH);    	
    }
    
    public void close() throws IOException
    {
    	if (!closed)
    	{
    		if (inHandshake)
    			warn(AlertDescription.user_canceled, "User canceled handshake");
    		    
    		closeTransport();
    	}
    }
    
    void fail(short alertDescription)
    {
        if (!closed)
        {
            try
            {
                raiseAlert(AlertLevel.fatal, alertDescription, null, null);
            }
            catch (Exception e)
            {
                // Ignore
            }

            failed = true;

            closeTransport();
        }
    }

    void failed()
    {
        if (!closed)
        {
            failed = true;

            closeTransport();
        }
    }

    void warn(short alertDescription, String message) throws IOException
    {
        raiseAlert(AlertLevel.warning, alertDescription, message, null);
    }

    private void closeTransport()
    {
        if (!closed)
        {
            try
            {
                if (!failed)
                    warn(AlertDescription.close_notify, null);
             
                channel.close();
            }
            catch (Exception e)
            {
            }

            closed = true;
        }
    }

    private void raiseAlert(short alertLevel, short alertDescription, String message, Throwable cause) throws IOException
    {
        peer.notifyAlertRaised(alertLevel, alertDescription, message, cause);

        ByteBuf error = Unpooled.buffer(2);
        error.writeByte(alertLevel);
        error.writeByte(alertDescription);

        sendRecord(ContentType.alert, error);
    }
    
    private void sendRecord(short contentType, ByteBuf buf) throws IOException
    {
    	if (writeVersion == null)
    		return;
            
    	int length=buf.readableBytes();
    	if (length > this.plaintextLimit)
    		throw new TlsFatalAlert(AlertDescription.internal_error);
        
    	if (length < 1 && contentType != ContentType.application_data)
    		throw new TlsFatalAlert(AlertDescription.internal_error);
            
    	int recordEpoch = writeEpoch.getEpoch();
        long recordSequenceNumber = writeEpoch.allocateSequenceNumber();
        
        byte[] plainData=new byte[length];
        buf.readBytes(plainData);
        byte[] ciphertext = writeEpoch.getCipher().encodePlaintext(getMacSequenceNumber(recordEpoch, recordSequenceNumber), contentType, plainData, 0, length);
        ByteBuf buffer=Unpooled.buffer(RECORD_HEADER_LENGTH + ciphertext.length);
        buffer.writeByte(contentType);
        buffer.writeByte(writeVersion.getMajorVersion());
        buffer.writeByte(writeVersion.getMinorVersion());
        buffer.writeShort(recordEpoch);
        DtlsHelper.writeUint48(recordSequenceNumber, buffer);
        
        buffer.writeShort(ciphertext.length);
        buffer.writeBytes(ciphertext);
        channel.writeAndFlush(new DatagramPacket(buffer, remoteAddress));
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number)
    {
    	return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
    }
}