package jpcap.packet;

import java.text.SimpleDateFormat;
import java.util.Date;

import jpcap.JpcapCaptor;

/** This is a root class of the all the packets captured by {@link JpcapCaptor Jpcap}. */
public class Packet implements java.io.Serializable
{
	private static final long serialVersionUID = 5182709860137479561L;
	private static final SimpleDateFormat sdf = new SimpleDateFormat("MM-dd HH:mm:ss.SSS");
	private static Date date = new Date();
	/** Captured timestamp (sec) */
	public long sec;
	
	/** Captured timestamp (micro sec) */
	public long usec;
	
	/** Captured length */
	public int caplen;
	
	/** Length of this packet */
	public int len;
	
	/** Datalink layer header */
	public DatalinkPacket datalink;

	/** Header data */
	public byte[] header;

	/** Packet data (excluding the header) */
	public byte[] data;

	/**
	 * Returned by JpcapCaptor.getPacket() when EOF was reached while reading from an offline file.
	 */
	public static final Packet EOF=new Packet();
	
	void setPacketValue(long sec,long usec,int caplen,int len){
		this.sec=sec;this.usec=usec;
		this.caplen=caplen;
		this.len=len;
	}

	void setDatalinkPacket(DatalinkPacket p){
		datalink=p;
		if (p instanceof W80211Packet) {
			this.data = ((W80211Packet)p).getDataFrame();
			this.header = new byte[0];
		}
	}
	
	void setPacketData(byte[] data){
		this.data=data;
	}
	
	void setPacketHeader(byte[] header){
		this.header=header;
	}
	
	/** Returns a string representation of this packet<BR>
         * Format: sec:usec
         * @return a string representation of this packet
         */
	public String toString(){
		// for test
		//date.setTime(sec * 1000L + usec);
		//String strDate = sdf.format(date);
		//return strDate;

		return sec+":"+usec;
	}
}
