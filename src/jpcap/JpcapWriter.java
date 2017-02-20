package jpcap;

import android.util.Log;
import jpcap.packet.Packet;
import pcapmonitor.JpcapTools;

/** This class is used to save the captured packets into a file. */
public class JpcapWriter
{
	private native String nativeOpenDumpFile(String filename,int ID);
	
	private JpcapWriter(JpcapCaptor jpcap,String filename)
			throws java.io.IOException{
		String ret = nativeOpenDumpFile(filename,jpcap.ID);
		
		if(ret != null) { //error
			Log.e(JpcapTools.TAG, ret);
			throw new java.io.IOException(ret);
		}
	}
	
	/** Opens a file to save the captured packets.
     * @param jpcap instance of JpcapCaptor that was used to capture (load) packets
     * @param filename filename
     * @throws IOException If the file cannot be opened
     */
	public static JpcapWriter openDumpFile(JpcapCaptor jpcap,String filename) throws java.io.IOException{
		return new JpcapWriter(jpcap,filename);
	}
	
	/** Closes the opened file. */
	public native void close();
	
	/** Saves a packet into the file.
         * @param packet Packet to be saved
         */
	public native void writePacket(Packet packet);
	
    static {
        try {
            JpcapCaptor.loadLibrary();
        } catch (UnsatisfiedLinkError ignore) {
            // see notes below the above call for why we eat this.
        }
    }

}
