package jpcap.packet;

public class WlanRadioTap implements java.io.Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 6164113297280610289L;
	
	// ieee80211_radiotap_header - START ---

	public static final byte IEEE80211_RADIOTAP_TSFT = 0;
	public static final byte IEEE80211_RADIOTAP_FLAGS = 1;
	public static final byte IEEE80211_RADIOTAP_RATE = 2;
	public static final byte IEEE80211_RADIOTAP_CHANNEL = 3;
	public static final byte IEEE80211_RADIOTAP_FHSS = 4;
	public static final byte IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5;
	public static final byte IEEE80211_RADIOTAP_DBM_ANTNOISE = 6;
	public static final byte IEEE80211_RADIOTAP_LOCK_QUALITY = 7;
	public static final byte IEEE80211_RADIOTAP_TX_ATTENUATION = 8;
	public static final byte IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9;
	public static final byte IEEE80211_RADIOTAP_DBM_TX_POWER = 10;
	public static final byte IEEE80211_RADIOTAP_ANTENNA = 11;
	public static final byte IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12;
	public static final byte IEEE80211_RADIOTAP_DB_ANTNOISE = 13;
	public static final byte IEEE80211_RADIOTAP_RX_FLAGS = 14;
	/* NB: gap for netbsd definitions */
	public static final byte IEEE80211_RADIOTAP_XCHANNEL = 18;
	public static final byte IEEE80211_RADIOTAP_MCS = 19;
	public static final byte IEEE80211_RADIOTAP_NAMESPACE = 29;
	public static final byte IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30;
	public static final byte IEEE80211_RADIOTAP_EXT = 31;

	/*
	 * Version 0. Only increases for drastic changes, introduction of compatible
	 * new fields does not count.
	 */
	private byte version = 0x00;

	private byte pad = 0x00;
	/*
	 * length of the whole header in bytes, including it_version, it_pad,
	 * it_len, and data fields.
	 */
	private short len = 0;

	/*
	 * A bitmap telling which fields are present. Set bit 31 (0x80000000) to
	 * extend the bitmap by another 32 bits. Additional extensions are made by
	 * setting bit 31.
	 */
	private int present = 0;

	// ieee80211_radiotap_header - END ----


	// Present flags - START -----
	/**
	 * Value in microseconds of the MAC's 64-bit 802.11 Time Synchronization
	 * Function timer when the first bit of the MPDU arrived at the MAC. For
	 * received frames only.
	 */
	private Long TFST = -1l;

	/** Properties of transmitted and received frames. */
	private byte flags = 0;

	/** TX/RX data rate in Mbps */
	private float dataRate = 0.0f;

	/** Tx/Rx frequency in MHz */
	private int channel = 0;
	private int channelflags = 0;
	
	/** The hop set and pattern for frequency-hopping radios. */
	private byte FHSS = 0x00;

	/**
	 * RF signal power at the antenna. This field contains a single signed 8-bit
	 * value, which indicates the RF signal power at the antenna, in decibels
	 * difference from 1mW.
	 */
	private byte dbmAntSignal = 0x00;

	/**
	 * RF noise power at the antenna. This field contains a single signed 8-bit
	 * value, which indicates the RF signal power at the antenna, in decibels
	 * difference from 1mW.
	 */
	private byte dbmAntNoise = 0x00;

	/**
	 * Quality of Barker code lock. Unitless. Monotonically nondecreasing with
	 * "better" lock strength. Called "Signal Quality" in datasheets
	 */
	private int lockQuality = 0;

	/**
	 * Transmit power expressed as decibel distance from max power set at
	 * factory calibration. 0 is max power. Monotonically nondecreasing with
	 * lower power levels.
	 */
	private int txAttenuation = 0;

	/**
	 * Transmit power expressed as decibel distance from max power set at
	 * factory calibration. 0 is max power. Monotonically nondecreasing with
	 * lower power levels.
	 */
	private int dbTxAttenuation = 0;

	/**
	 * Transmit power expressed as dBm (decibels from a 1 milliwatt reference).
	 * This is the absolute power level measured at the antenna port.
	 */
	private byte dbmTxPower = 0;

	/**
	 * Unitless indication of the Rx/Tx antenna for this packet. The first
	 * antenna is antenna 0.
	 */
	private byte antenna = 0x00;

	/**
	 * RF signal power at the antenna, decibel difference from an arbitrary,
	 * fixed reference. This field contains a single unsigned 8-bit value.
	 */
	private byte dbAntennaSignal = 0x00;

	/**
	 * RF noise power at the antenna, decibel difference from an arbitrary,
	 * fixed reference. This field contains a single unsigned 8-bit value.
	 */
	private byte dbAntennaNoise = 0x00;

	/** Properties of received frames. */
	private short rxFlags = 0;

	/**
	 * Modulation coding scheme
	 */
	private byte mcs = 0x00;

	/**
	 * Define if a PLCP (Physical Layer Convergence Protocol) CRC error was detected on this frame
	 * @return
	 */
	private boolean isPlcpCrcErrors= false;


	private boolean bTfst = false;
	private boolean bFlagsPres = false;
	private boolean bDataRate = false;
	private boolean bChannel = false;
	private boolean bFhss = false;
	private boolean bDbmAntSignal = false;
	private boolean bDbmAntNoise = false;
	private boolean bLockQuality = false;
	private boolean bTxAttenuation = false;
	private boolean bDbTxAttenuation = false;
	private boolean bDbmTxPower = false;
	private boolean bAntenna = false;
	private boolean bDbAntennaSignal = false;
	private boolean bDbAntennaNoise = false;
	private boolean bRxFlags = false;
	private boolean bMcs = false;
	// Present flags - END -----
	
	/**
	 * @param version
	 * @param pad
	 * @param len
	 * @param present
	 */
	public WlanRadioTap(byte version, byte pad, short len, int present) {
		super();
		this.version = version;
		this.pad = pad;
		this.len = len;
		this.present = present;
	}

	/**
	 * @return the version
	 */
	public byte getVersion() {
		return version;
	}

	/**
	 * @param version the version to set
	 */
	public void setVersion(byte version) {
		this.version = version;
	}

	/**
	 * @return the pad
	 */
	public byte getPad() {
		return pad;
	}

	/**
	 * @param pad the pad to set
	 */
	public void setPad(byte pad) {
		this.pad = pad;
	}

	/**
	 * @return the len
	 */
	public short getLen() {
		return len;
	}

	/**
	 * @param len the len to set
	 */
	public void setLen(short len) {
		this.len = len;
	}

	/**
	 * @return the present
	 */
	public int getPresent() {
		return present;
	}

	/**
	 * @param present the present to set
	 */
	public void setPresent(int present) {
		this.present = present;
	}

	/**
	 * @return the tFST
	 */
	public Long getTFST() {
		return TFST;
	}

	/**
	 * @param tFST the tFST to set
	 */
	public void setTFST(Long tFST) {
		TFST = tFST;
	}

	/**
	 * @return the flags
	 */
	public byte getFlags() {
		return flags;
	}

	/**
	 * @param flags the flags to set
	 */
	public void setFlags(byte flags) {
		this.flags = flags;
	}

	/**
	 * @return the dataRate
	 */
	public float getDataRate() {
		return dataRate;
	}

	/**
	 * @param dataRate the dataRate to set
	 */
	public void setDataRate(float dataRate) {
		this.dataRate = dataRate;
	}

	/**
	 * @return the channel
	 */
	public int getChannel() {
		return channel;
	}

	/**
	 * @param channel the channel to set
	 */
	public void setChannel(int channel) {
		this.channel = channel;
	}

	/**
	 * @return the channelflags
	 */
	public int getChannelflags() {
		return channelflags;
	}

	/**
	 * @param channelflags the channelflags to set
	 */
	public void setChannelflags(int channelflags) {
		this.channelflags = channelflags;
	}

	/**
	 * @param channel the channel to set
	 */
	public void setChannel(int channel, int channelflags) {
		this.channel = channel;
		this.channelflags = channelflags;
	}

	
	/**
	 * @return the fHSS
	 */
	public byte getFHSS() {
		return FHSS;
	}

	/**
	 * @param fHSS the fHSS to set
	 */
	public void setFHSS(byte fHSS) {
		FHSS = fHSS;
	}

	/**
	 * @return the dbmAntSignal
	 */
	public byte getDbmAntSignal() {
		return dbmAntSignal;
	}

	/**
	 * @param dbmAntSignal the dbmAntSignal to set
	 */
	public void setDbmAntSignal(byte dbmAntSignal) {
		this.dbmAntSignal = dbmAntSignal;
	}

	/**
	 * @return the dbmAntNoise
	 */
	public byte getDbmAntNoise() {
		return dbmAntNoise;
	}

	/**
	 * @param dbmAntNoise the dbmAntNoise to set
	 */
	public void setDbmAntNoise(byte dbmAntNoise) {
		this.dbmAntNoise = dbmAntNoise;
	}

	/**
	 * @return the lockQuality
	 */
	public int getLockQuality() {
		return lockQuality;
	}

	/**
	 * @param lockQuality the lockQuality to set
	 */
	public void setLockQuality(int lockQuality) {
		this.lockQuality = lockQuality;
	}

	/**
	 * @return the txAttenuation
	 */
	public int getTxAttenuation() {
		return txAttenuation;
	}

	/**
	 * @param txAttenuation the txAttenuation to set
	 */
	public void setTxAttenuation(int txAttenuation) {
		this.txAttenuation = txAttenuation;
	}

	/**
	 * @return the dbTxAttenuation
	 */
	public int getDbTxAttenuation() {
		return dbTxAttenuation;
	}

	/**
	 * @param dbTxAttenuation the dbTxAttenuation to set
	 */
	public void setDbTxAttenuation(int dbTxAttenuation) {
		this.dbTxAttenuation = dbTxAttenuation;
	}

	/**
	 * @return the dbmTxPower
	 */
	public byte getDbmTxPower() {
		return dbmTxPower;
	}

	/**
	 * @param dbmTxPower the dbmTxPower to set
	 */
	public void setDbmTxPower(byte dbmTxPower) {
		this.dbmTxPower = dbmTxPower;
	}

	/**
	 * @return the antenna
	 */
	public byte getAntenna() {
		return antenna;
	}

	/**
	 * @param antenna the antenna to set
	 */
	public void setAntenna(byte antenna) {
		this.antenna = antenna;
	}

	/**
	 * @return the dbAntennaSignal
	 */
	public byte getDbAntennaSignal() {
		return dbAntennaSignal;
	}

	/**
	 * @param dbAntennaSignal the dbAntennaSignal to set
	 */
	public void setDbAntennaSignal(byte dbAntennaSignal) {
		this.dbAntennaSignal = dbAntennaSignal;
	}

	/**
	 * @return the dbAntennaNoise
	 */
	public byte getDbAntennaNoise() {
		return dbAntennaNoise;
	}

	/**
	 * @param dbAntennaNoise the dbAntennaNoise to set
	 */
	public void setDbAntennaNoise(byte dbAntennaNoise) {
		this.dbAntennaNoise = dbAntennaNoise;
	}

	/**
	 * @return the rxFlags
	 */
	public short getRxFlags() {
		return rxFlags;
	}

	/**
	 * @param rxFlags the rxFlags to set
	 */
	public void setRxFlags(short rxFlags) {
		this.rxFlags = rxFlags;
	}

	/**
	 * @return the mcs
	 */
	public byte getMcs() {
		return mcs;
	}

	/**
	 * @param mcs the mcs to set
	 */
	public void setMcs(byte mcs) {
		this.mcs = mcs;
	}

	/**
	 * @return the isPlcpCrcErrors
	 */
	public boolean isPlcpCrcErrors() {
		return isPlcpCrcErrors;
	}

	/**
	 * @param isPlcpCrcErrors the isPlcpCrcErrors to set
	 */
	public void setPlcpCrcErrors(boolean isPlcpCrcErrors) {
		this.isPlcpCrcErrors = isPlcpCrcErrors;
	}

	public void setRadioTapFlags(byte flag, float value) {
		switch (flag) {
			case IEEE80211_RADIOTAP_RATE:
				this.bDataRate = true;
				setDataRate((float)value);
				break;
			default:
				break;
		}
	}	
	
	public void setRadioTapFlags(byte flag, long value) {
		
		switch (flag) {
		case IEEE80211_RADIOTAP_TSFT:
			this.bTfst = true;
			setTFST(value);
			break;

		default:
			break;
		}
	}	
	
	public void setRadioTapFlags(byte flag, int value, int value2) {
		
		switch (flag) {
		//case IEEE80211_RADIOTAP_TSFT:
		//	this.bTfst = true;
		//	setTFST(value);
		//	break;
		case IEEE80211_RADIOTAP_FLAGS:
			this.bFlagsPres = true;
			setFlags((byte)value);
			break;
		case IEEE80211_RADIOTAP_RATE:
			this.bDataRate = true;
			setDataRate(value);
			break;
		case IEEE80211_RADIOTAP_CHANNEL:
		case IEEE80211_RADIOTAP_XCHANNEL:
			this.bChannel = true;
			setChannel(value, value); 
			break;
		case IEEE80211_RADIOTAP_FHSS:
			this.bFhss = true;
			setFHSS((byte)value);
			break;
		case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
			this.bDbmAntSignal = true;
			setDbmAntSignal((byte)value);
			break;
		case IEEE80211_RADIOTAP_DBM_ANTNOISE:
			this.bDbmAntNoise = true;
			setDbmAntNoise((byte)value);
			break;
		case IEEE80211_RADIOTAP_LOCK_QUALITY:
			this.bLockQuality = true;
			setLockQuality(value);
			break;
		case IEEE80211_RADIOTAP_TX_ATTENUATION:
			this.bTxAttenuation = true;
			setTxAttenuation(value);
			break;
		case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
			this.bDbTxAttenuation = true;
			setDbTxAttenuation(value);
			break;
		case IEEE80211_RADIOTAP_DBM_TX_POWER:
			this.bDbmTxPower = true;
			setDbmTxPower((byte)value);
			break;
		case IEEE80211_RADIOTAP_ANTENNA:
			this.bAntenna = true;
			setAntenna((byte)value);
			break;
		case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
			this.bDbAntennaSignal = true;
			setDbAntennaSignal((byte)value);
			break;
		case IEEE80211_RADIOTAP_DB_ANTNOISE:
			this.bDbAntennaNoise = true;
			setDbAntennaNoise((byte)value);
			break;
		case IEEE80211_RADIOTAP_RX_FLAGS:
			this.bRxFlags = true;
			setRxFlags((short)value);
			break;
		case IEEE80211_RADIOTAP_MCS:
			this.bMcs = true;
			setMcs((byte)value);
			break;

		default:
			break;
		}
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return "RadioTap [version=" + version + ", pad=" + pad + ", len=" + len + ", present=" + Integer.toBinaryString(present) + ", TFST="
				+ TFST + ", flags=" + Integer.toBinaryString(flags) + ", dataRate=" + dataRate + ", channel=" + channel + ", channelflags="
				+ Integer.toBinaryString(channelflags) + ", FHSS=" + FHSS + ", dbmAntSignal=" + dbmAntSignal + ", dbmAntNoise=" + dbmAntNoise
				+ ", lockQuality=" + lockQuality + ", txAttenuation=" + txAttenuation + ", dbTxAttenuation="
				+ dbTxAttenuation + ", dbmTxPower=" + dbmTxPower + ", antenna=" + antenna + ", dbAntennaSignal="
				+ dbAntennaSignal + ", dbAntennaNoise=" + dbAntennaNoise + ", rxFlags=" + rxFlags + ", mcs=" + mcs
				+ ", isPlcpCrcErrors=" + isPlcpCrcErrors + "]";
	}	
	
}
