package com.mobius.software.iot.dal.crypto;

import org.bouncycastle.crypto.tls.ProtocolVersion;

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

public class PendingTransportData 
{
	short type;
	ProtocolVersion version;
	int epoch;
    long seq;
	private byte[] realData;	
	
	public PendingTransportData(short type,ProtocolVersion version, int epoch, long seq,byte[] realData)
	{
		this.type=type;
		this.version=version;
		this.epoch=epoch;
		this.seq=seq;
		this.realData=realData;		
	}

	public short getType() 
	{
		return type;
	}

	public ProtocolVersion getVersion() 
	{
		return version;
	}

	public int getEpoch() 
	{
		return epoch;
	}

	public long getSeq() 
	{
		return seq;
	}

	public byte[] getRealData() 
	{
		return realData;
	}		
}