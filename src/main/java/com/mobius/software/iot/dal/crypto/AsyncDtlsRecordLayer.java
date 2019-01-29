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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

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
	public static final int MAX_FRAGMENT_LENGTH = 1400;
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
    
    private AtomicLong lastProcessedTransportSequence=new AtomicLong(Integer.MIN_VALUE);
    private ConcurrentHashMap<Integer,ConcurrentHashMap<Long, PendingTransportData>> pendingTransportMessages=new ConcurrentHashMap<Integer,ConcurrentHashMap<Long,PendingTransportData>>();
    
    public AsyncDtlsRecordLayer(TlsHandshakeHash handshakeHash,HandshakeHandler handshakeHandler,Channel channel,TlsContext context, TlsPeer peer,InetSocketAddress remoteAddress, InetSocketAddress localAddress)
    {
    	this.handshakeHash=handshakeHash;
    	this.channel=channel;
    	this.remoteAddress=remoteAddress;
    	this.handshakeHandler=handshakeHandler;
    	this.peer = peer;
        this.inHandshake = true;
        this.currentEpoch = new AsyncDtlsEpoch(0, new TlsNullCipher(context));
        this.pendingEpoch = null;
        this.pendingTransportMessages.put(this.currentEpoch.getEpoch(), new ConcurrentHashMap<Long, PendingTransportData>());
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
    
    private void processHandshakeQueue(HandshakeHeader handshakeHeader,ByteBuf buffer,byte[] packetData) throws IOException
    {
    	if(handshakeHeader.getMessageType()!=null && handshakeHandler!=null)
			handshakeHandler.handleHandshake(handshakeHeader.getMessageType(), buffer);
		
		byte[] pseudoHeader=new byte[DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH];
		ByteBuf headerBuffer=Unpooled.wrappedBuffer(pseudoHeader);
		headerBuffer.writerIndex(0);
		DtlsHelper.writeHandshakeHeader(handshakeHeader.getMessageSequence(), handshakeHeader.getMessageType(), headerBuffer, handshakeHeader.getTotalLength());
		headerBuffer.readerIndex(0);
		handshakeHash.update(pseudoHeader, 0, pseudoHeader.length); 
		handshakeHash.update(packetData, 0, packetData.length);
		
		if(handshakeHeader.getMessageType()!=null && handshakeHandler!=null)
			handshakeHandler.postProcessHandshake(handshakeHeader.getMessageType(), buffer);
    }
    
    public List<ByteBuf> receive(ByteBuf record) throws IOException
    {
    	while(record.readableBytes()>RECORD_HEADER_LENGTH)
    	{
    		short type = (short)(record.readByte() & 0x00FF);
	    	ProtocolVersion version=ProtocolVersion.get(record.readByte() & 0xFF, record.readByte() & 0xFF);
	    	int epoch = record.readUnsignedShort();
	        long seq = DtlsHelper.readUint48(record);
	        
	        //just reading length,not using it
	        short packetLength=record.readShort();
	        byte[] realData=new byte[packetLength];
	        record.readBytes(realData);
	        
	        lastProcessedTransportSequence.compareAndSet(Integer.MIN_VALUE, seq);
	        if(pendingTransportMessages.get(epoch)==null)
	        	pendingTransportMessages.putIfAbsent(epoch, new ConcurrentHashMap<Long, PendingTransportData>());
	        
	        pendingTransportMessages.get(epoch).put(seq, new PendingTransportData(type, version, epoch, seq, realData));
    	}
	        
    	List<ByteBuf> outputList=new ArrayList<ByteBuf>();
    	Boolean shouldContinue=true;
    	while(shouldContinue)
    	{
    		PendingTransportData nextPacket=pendingTransportMessages.get(readEpoch.getEpoch()).remove(lastProcessedTransportSequence.get());
        	if(nextPacket==null)
        		shouldContinue=false;
        	else 
        	{
	    		AsyncDtlsEpoch recordEpoch = null;
		        if (nextPacket.getEpoch() == readEpoch.getEpoch())
		            recordEpoch = readEpoch;
	
		        if (recordEpoch == null)
		        {
		        	lastProcessedTransportSequence.incrementAndGet();
		        	continue;
		        }
		
		        if (recordEpoch.getReplayWindow().shouldDiscard(nextPacket.getSeq()))
		        {
		        	lastProcessedTransportSequence.incrementAndGet();
		        	continue;
		        }
		
		        if (!nextPacket.getVersion().isDTLS())
		        {
		        	lastProcessedTransportSequence.incrementAndGet();
		        	continue;
		        }
		
		        if (readVersion != null && !readVersion.equals(nextPacket.getVersion()))
		        {
		        	lastProcessedTransportSequence.incrementAndGet();
		        	continue;
		        }
		        
		        byte[] plaintext = recordEpoch.getCipher().decodeCiphertext(getMacSequenceNumber(recordEpoch.getEpoch(), nextPacket.getSeq()), nextPacket.getType(), nextPacket.getRealData(), 0, nextPacket.getRealData().length);
		        ByteBuf output=Unpooled.wrappedBuffer(plaintext);
		        
		        recordEpoch.getReplayWindow().reportAuthenticated(nextPacket.getSeq());
		        /*if (plaintext.length > this.plaintextLimit)
		        	continue;*/
		
		        if (readVersion == null)
		            readVersion = nextPacket.getVersion();
		        
		        switch (nextPacket.getType())
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
			
			            lastProcessedTransportSequence.incrementAndGet();
			            continue;
			        case ContentType.application_data:
			            if (inHandshake)
			            {
			            	lastProcessedTransportSequence.incrementAndGet();
			            	continue;
			            }
			            break;
			        case ContentType.change_cipher_spec:
			        	while(output.readableBytes()>0)
			            {
			            	
			                short message = (short)(output.readByte() & 0x0FF);
			                if (message != ChangeCipherSpec.change_cipher_spec)
			                {
			                	lastProcessedTransportSequence.incrementAndGet();
			                	continue;
			                }
			            
			                if (pendingEpoch != null)
			                {
			                	lastProcessedTransportSequence.set(-1);
			                	pendingTransportMessages.putIfAbsent(this.pendingEpoch.getEpoch(), new ConcurrentHashMap<Long, PendingTransportData>());
			                    readEpoch = pendingEpoch;
			                }
			            }
			
			        	lastProcessedTransportSequence.incrementAndGet();
			        	continue;
			        case ContentType.handshake:
			            if (!inHandshake)
			            {
			            	lastProcessedTransportSequence.incrementAndGet();
			                continue;
			            }
			                
			            HandshakeHeader handshakeHeader=DtlsHelper.readHandshakeHeader(output);
			            
			            if(handshakeHeader!=null)
			            {
			            	if(!handshakeHeader.getFragmentLength().equals(handshakeHeader.getTotalLength()))
			            	{
			            		PendingMessageData data=pendingBuffers.get(handshakeHeader.getMessageSequence());
			            		if(data==null)
			            		{
			            			data=new PendingMessageData(Unpooled.buffer(handshakeHeader.getTotalLength()));
			            			PendingMessageData oldData=pendingBuffers.putIfAbsent(handshakeHeader.getMessageSequence(),data);
			            			if(oldData!=null)
			            				data=oldData;
			            		}
			            			
			            		data.writeBytes(output, handshakeHeader.getFragmentOffset());
			            		if(data.getWrottenBytes().equals(handshakeHeader.getTotalLength()))
			            		{
			            			data.getBuffer().writerIndex(handshakeHeader.getTotalLength());
			            			byte[] packetData=null;
			            			ByteBuf copy=data.getBuffer().copy();
			            			packetData=new byte[copy.readableBytes()];
			            			copy.readBytes(packetData);	
			            			
			            			processHandshakeQueue(handshakeHeader,data.getBuffer(),packetData);
			            			
			            			pendingBuffers.remove(handshakeHeader.getMessageSequence());
			            		}
			            	}
			            	else
			            	{
			            		byte[] packetData=null;
			            		ByteBuf copy=output.copy();
		            			packetData=new byte[copy.readableBytes()];
		            			copy.readBytes(packetData);
		            			
		            			processHandshakeQueue(handshakeHeader,output,packetData);	            				            				            	
			            	}
			            }
			            
			            lastProcessedTransportSequence.incrementAndGet();
			            continue;
			        case ContentType.heartbeat:
			        	lastProcessedTransportSequence.incrementAndGet();
			        	continue;	       
		        }
		        
		        outputList.add(output);
		        lastProcessedTransportSequence.incrementAndGet();
    		}
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
        channel.writeAndFlush(new DatagramPacket(buffer, remoteAddress, (InetSocketAddress) channel.localAddress()));
    }

    private static long getMacSequenceNumber(int epoch, long sequence_number)
    {
    	return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
    }
}