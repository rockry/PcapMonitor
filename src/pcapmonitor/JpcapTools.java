package pcapmonitor;


import java.io.IOException;
import java.io.PrintStream;
import java.text.SimpleDateFormat;
import java.util.Date;

import android.util.Log;
import android.widget.Toast;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.JpcapWriter;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import main.PCapServer;
import packetProcessor.IPacketReader;
import packetProcessor.IPacketWriter;
import packetProcessor.PacketReaderFactory;
import packetProcessor.PacketWriterFactory;

public class JpcapTools {

	public static final String TAG = "Jpcap";
	public static final int LIST_INIT_CAPACITY = 1024;
	private static PCapServer mPcapServer = null;
	private static NetworkInterface[] mDevices = null;
	private static Date mDate = new Date();
	private static final SimpleDateFormat mSdf = new SimpleDateFormat("MM-dd HH:mm:ss.SSS");
	private static StringBuffer mSBDate = new StringBuffer(25);

    public static final boolean IS_WIFI_CHIP_VENDOR_QCT = System.getProperty("wlan.chip.vendor", "brcm").equals("qcom");	
    public static final boolean IS_WIFI_CHIP_VENDOR_BRCM = System.getProperty("wlan.chip.vendor", "qcom").equals("brcm");	
    
    public static void ReadPacketFromFile(String fileName, IWidgetViewActivity writer) {

    	if (fileName == null || fileName.isEmpty()) return;
    	
    	IPacketReader source =  PacketReaderFactory.getPacketReader(fileName);
    	IPacketWriter packetWriter;
    	if (writer == null) {
    		packetWriter = getSystemWriter();		
    	} else {
    		packetWriter = PacketWriterFactory.getPacketWriter(writer, null); 	
    	}
		source.setWriter(packetWriter);
		PCapServer server = new PCapServer(source);
		server.start();
		
    }
  
    private  static IPacketWriter getSystemWriter() {
		PrintStream printStream = System.out;

		IPacketWriter systemWriter = PacketWriterFactory.getPacketWriter(printStream, null);
		return systemWriter;
	}
	
	private static IPacketWriter getPacketFileWriter(JpcapCaptor captor, String fileName) throws IOException {

		if (fileName.isEmpty()) return null;
		
		JpcapWriter fileWriter = JpcapWriter.openDumpFile(captor, fileName);
		IPacketWriter filePacketWriter = PacketWriterFactory
				.getPacketWriter(fileWriter, null);

		return filePacketWriter;
	}

	private static IPacketWriter getNetworkInterfacePacketWriter(NetworkInterface device) throws IOException {
		JpcapSender sender = JpcapSender.openDevice(device);
		IPacketWriter networkWriter = PacketWriterFactory.getPacketWriter(sender, null);

		return networkWriter;
	}
	
    public static void ReadPacketFromInterface(NetworkInterface device, Object writer, String fileName) {
    	if (mPcapServer != null) {
    		mPcapServer.stop();
    		mPcapServer = null;
    	}
    	
    	if (device == null) return;
    	
    	IPacketReader source = PacketReaderFactory.getPacketReader(device);	
    	IPacketWriter packetWriter = null;
    	JpcapWriter fileWriter = null;
    	if (writer == null) {
    		packetWriter = getSystemWriter();		
    	} else if (writer instanceof IWidgetViewActivity) {
    		if ((fileName != null) && (fileName.isEmpty() == false)){
    			try {
					fileWriter = JpcapWriter.openDumpFile(source.getCaptor(), fileName);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					Log.e(TAG, "ReadPacketFromInterface: JpcapWriter.openDumpFile Error!!!!");
					fileWriter = null;
				}   			
    		}
    		packetWriter = PacketWriterFactory.getPacketWriter(writer, fileWriter); 	
    	} else if (writer instanceof String) {
    		try {
				packetWriter = getPacketFileWriter(source.getCaptor(), (String)writer);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				Log.e(TAG, "ReadPacketFromInterface: getPacketFileWriter Error!!!!");
			}
    	} else if (writer instanceof NetworkInterface) {
    		try {
				packetWriter = getNetworkInterfacePacketWriter((NetworkInterface)writer);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				Log.e(TAG, "ReadPacketFromInterface: getNetworkInterfacePacketWriter Error!!!!");
			}
    	} else {
    		Log.e(TAG, "ReadPacketFromInterface parameter - " + writer.toString());
    		packetWriter = getSystemWriter();
    	}
    			
    	if (packetWriter == null) {
    		Log.e(TAG, "ReadPacketFromInterface - packetWriter is null!!!!");
    		return;
    	}
    	
		source.setWriter(packetWriter);
		mPcapServer = new PCapServer(source);
		mPcapServer.start();
    }
   
    public static void StopReadPacketFromInterface() {
    	if (mPcapServer == null) {
    		return;
    	}

		mPcapServer.stop();
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
		
		mPcapServer = null;
    }
    
    public static String ReadInterface() {
        StringBuffer sb = new StringBuffer("");

        NetworkInterface[] devices = getNetworkInterface();

        if (devices == null) {
            sb.append("devices is null..............");
            return sb.toString();
        }
        // for each network interface
        for (int i = 0; i < devices.length; i++) {
            // print out its name and description
            sb.append(i + ": " + devices[i].name + "(" + devices[i].description + ")");

            // print out its datalink name and description
            sb.append(" datalink: " + devices[i].datalink_name + "("
                    + devices[i].datalink_description + ")");

            // print out its MAC address
            sb.append(" MAC address:");

            for (byte b : devices[i].mac_address) {
                sb.append(Integer.toHexString(b & 0xff) + ":");
            }

            sb.append("\n");

            // print out its IP address, subnet mask and broadcast address
            for (NetworkInterfaceAddress a : devices[i].addresses) {
                sb.append(" address:" + a.address + " " + a.subnet
                        + " " + a.broadcast);
            }

        }
        return sb.toString();
    }
    
    public static String[] ReadInterfaceEx() {
    	
    	StringBuffer sb = new StringBuffer();
    	NetworkInterface[] devices = getNetworkInterfaceForce();
        if (devices == null) {
        	return null;
        }       
        
        String[] interfaceLists = new String[devices.length];
        
        // for each network interface
        for (int i = 0; i < devices.length; i++) {
        	sb.delete(0, sb.length());
            // print out its name and description
            sb.append(i + ": " + devices[i].name);

            sb.append("(");
            
            for (byte b : devices[i].mac_address) {
            	String strHex = Integer.toHexString(b & 0xff);
            	if (strHex.length() == 1) {
            		sb.append("0" + strHex + ":");
            	} else {
            		sb.append(strHex + ":");
            	}
            }
            
            sb.deleteCharAt(sb.length()-1);
            sb.append(")");

            interfaceLists[i] = sb.toString();
        }
        
        return interfaceLists;
    }
    
    public static NetworkInterface[] getNetworkInterface() {
    	if (mDevices == null) {
        	mDevices = JpcapCaptor.getDeviceList();
            if (mDevices == null) {
            	Log.e(TAG, "NetworkInterface (mDevices) is null!!!!");
            } else {  
            	// for debug
            	Log.d(TAG, displayNetworkInterfaces(mDevices));
            }
    	}
    	
    	return mDevices;
    }
    
    public static NetworkInterface[] getNetworkInterfaceForce() {
    	if (mDevices != null) {
    		mDevices = null;
    	}
    	
    	mDevices = JpcapCaptor.getDeviceList();
        if (mDevices == null) {
        	Log.e(TAG, "NetworkInterface (mDevices) is null!!!!");
        } else {  
        	// for debug
        	Log.d(TAG, displayNetworkInterfaces(mDevices));
        }
    	
    	return mDevices;
    }
    
    public static String displayNetworkInterfaces(NetworkInterface[] networkIfaces) {
    	if (networkIfaces == null || networkIfaces.length == 0) return "";
    	StringBuffer sb = new StringBuffer();
    	for (NetworkInterface iface : networkIfaces) {
    		sb.append(iface.toString());
    		sb.append("\n");
    	}
    	
    	return sb.toString();
    }
    
    public static String getDate(int position, long seconds, long microseconds, boolean bShowDateTypeHumanType) {
		mSBDate.delete(0, 24);
		
		if (position > 0) {
			mSBDate.append(position + " ");
		}
		
		if (bShowDateTypeHumanType == true) {				
			mDate.setTime((seconds * 1000) + (microseconds / 1000));
			mSBDate.append(mSdf.format(mDate));
		} else {
			mSBDate.append(seconds+"."+ microseconds);
		}
		
		//Log.d(JpcapTools.TAG, "[Time] " + mSBDate.toString());
		
		return mSBDate.toString();
    }
}
