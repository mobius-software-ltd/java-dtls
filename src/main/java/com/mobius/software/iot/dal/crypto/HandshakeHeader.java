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

public class HandshakeHeader 
{
	private Integer fragmentOffset;
	private Integer fragmentLength;
	private Integer totalLength;
	private MessageType messageType;
	private Short messageSequence;
	
	public HandshakeHeader(Integer fragmentOffset,Integer fragmentLength,Integer totalLength,MessageType messageType,Short messageSequence)
	{
		this.fragmentOffset=fragmentOffset;
		this.fragmentLength=fragmentLength;
		this.totalLength=totalLength;
		this.messageType=messageType;
		this.messageSequence=messageSequence;
	}

	public Integer getFragmentOffset() 
	{
		return fragmentOffset;
	}

	public void setFragmentOffset(Integer fragmentOffset) 
	{
		this.fragmentOffset = fragmentOffset;
	}

	public Integer getFragmentLength() 
	{
		return fragmentLength;
	}

	public void setFragmentLength(Integer fragmentLength) 
	{
		this.fragmentLength = fragmentLength;
	}

	public Integer getTotalLength() 
	{
		return totalLength;
	}

	public void setTotalLength(Integer totalLength) 
	{
		this.totalLength = totalLength;
	}

	public MessageType getMessageType() 
	{
		return messageType;
	}

	public void setMessageType(MessageType messageType) 
	{
		this.messageType = messageType;
	}

	public Short getMessageSequence() 
	{
		return messageSequence;
	}

	public void setMessageSequence(Short messageSequence) 
	{
		this.messageSequence = messageSequence;
	}		
}