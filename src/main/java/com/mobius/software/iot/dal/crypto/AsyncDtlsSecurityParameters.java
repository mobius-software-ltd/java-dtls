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

import org.bouncycastle.crypto.tls.CompressionMethod;
import org.bouncycastle.crypto.tls.SecurityParameters;

public class AsyncDtlsSecurityParameters extends SecurityParameters
{
	int entity = -1;
	int cipherSuite = -1;
	short compressionAlgorithm = CompressionMethod._null;
	int prfAlgorithm = -1;
	int verifyDataLength = -1;
	byte[] masterSecret = null;
	byte[] clientRandom = null;
	byte[] serverRandom = null;
	byte[] sessionHash = null;
	byte[] pskIdentity = null;
	byte[] srpIdentity = null;

	short maxFragmentLength = -1;
	boolean truncatedHMac = false;
	boolean encryptThenMAC = false;
	boolean extendedMasterSecret = false;
	    
	public int getEntity() 
	{
		return entity;
	}
	
    public void setEntity(int entity) 
    {
		this.entity = entity;
	}
	
    public int getCipherSuite() 
    {
		return cipherSuite;
	}
	
    public void setCipherSuite(int cipherSuite) 
    {
		this.cipherSuite = cipherSuite;
	}
	
    public short getCompressionAlgorithm() 
    {
		return compressionAlgorithm;
	}
	
    public void setCompressionAlgorithm(short compressionAlgorithm) 
    {
		this.compressionAlgorithm = compressionAlgorithm;
	}
	
    public int getPrfAlgorithm() 
    {
		return prfAlgorithm;
	}
	
    public void setPrfAlgorithm(int prfAlgorithm) 
    {
		this.prfAlgorithm = prfAlgorithm;
	}
	
    public int getVerifyDataLength() 
    {
		return verifyDataLength;
	}
	
    public void setVerifyDataLength(int verifyDataLength) 
    {
		this.verifyDataLength = verifyDataLength;
	}
	
    public byte[] getMasterSecret() 
    {
		return masterSecret;
	}
	
    public void setMasterSecret(byte[] masterSecret) 
    {
		this.masterSecret = masterSecret;
	}
	
    public byte[] getClientRandom() 
    {
		return clientRandom;
	}
	
    public void setClientRandom(byte[] clientRandom) 
    {
		this.clientRandom = clientRandom;
	}
	
    public byte[] getServerRandom() 
    {
		return serverRandom;
	}
	
    public void setServerRandom(byte[] serverRandom) 
    {
		this.serverRandom = serverRandom;
	}
	
    public byte[] getSessionHash() 
    {
		return sessionHash;
	}
	
    public void setSessionHash(byte[] sessionHash) 
    {
		this.sessionHash = sessionHash;
	}
	
    public byte[] getPskIdentity() 
    {
		return pskIdentity;
	}
	
    public void setPskIdentity(byte[] pskIdentity) 
    {
		this.pskIdentity = pskIdentity;
	}
	
    public byte[] getSrpIdentity() 
    {
		return srpIdentity;
	}
	
    public void setSrpIdentity(byte[] srpIdentity) 
    {
		this.srpIdentity = srpIdentity;
	}
	
    public short getMaxFragmentLength() 
    {
		return maxFragmentLength;
	}
	
    public void setMaxFragmentLength(short maxFragmentLength) 
    {
		this.maxFragmentLength = maxFragmentLength;
	}
	
    public boolean isTruncatedHMac() 
    {
		return truncatedHMac;
	}
	
    public void setTruncatedHMac(boolean truncatedHMac) 
    {
		this.truncatedHMac = truncatedHMac;
	}
	
    public boolean isEncryptThenMAC() 
    {
		return encryptThenMAC;
	}
	
    public void setEncryptThenMAC(boolean encryptThenMAC) 
    {
		this.encryptThenMAC = encryptThenMAC;
	}
	
    public boolean isExtendedMasterSecret() 
    {
    	return extendedMasterSecret;
	}
	
    public void setExtendedMasterSecret(boolean extendedMasterSecret) 
    {
    	this.extendedMasterSecret = extendedMasterSecret;
	}            
}