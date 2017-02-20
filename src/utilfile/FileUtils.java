package utilfile;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;

import android.util.Log;
import pcapmonitor.JpcapTools;

/**
 * A set of tools for file operations
 */
public class FileUtils {

	/** Filter which accepts every file */
	public static final String FILTER_ALLOW_ALL = "*.*";
	private static final int DLT_IEEE802_11_HEX = 0x69; // 105
	private static final int DLT_IEEE802_11_TYPE_POSITION = 20;

	/**
	 * This method checks that the file is accepted by the filter
	 * 
	 * @param file
	 *            - file that will be checked if there is a specific type
	 * @param filter
	 *            - criterion - the file type(for example ".jpg")
	 * @return true - if file meets the criterion - false otherwise.
	 */
	public static boolean accept(final File file, final String filter) {
		if (filter.compareTo(FILTER_ALLOW_ALL) == 0) {
			return true;
		}
		if (file.isDirectory()) {
			return true;
		}
		if (file.length() == 0) {
			return false;
		}
		
		int lastIndexOfPoint = file.getName().lastIndexOf('.');
		if (lastIndexOfPoint == -1) {
			return false;
		}
		String fileType = file.getName().substring(lastIndexOfPoint).toLowerCase();
		if (fileType.contains("pcap")) {
			return ".pcap".compareTo(filter) == 0;
		} else {
			return fileType.compareTo(filter) == 0;
		}
	}
	
	
	public static void makePcapFile(String inFilePath, String outFilePath) throws IOException {
		if (outFilePath.endsWith(".pcap") == false) {
			outFilePath += ".pcap";
		}
		
		if (JpcapTools.IS_WIFI_CHIP_VENDOR_QCT) {
			File inFile = new File(inFilePath);
			File outFile = new File(outFilePath);
			if (inFile.renameTo(outFile) == true) {
				Log.d(JpcapTools.TAG, "Save " + outFilePath + " success.");
			} else {
				Log.d(JpcapTools.TAG, "Save " + outFilePath + " fail.");
			}	
		} else {
			FileInputStream in = new FileInputStream(inFilePath);
			FileOutputStream out = new FileOutputStream(outFilePath);
			BufferedInputStream inBuf = new BufferedInputStream(in);
			BufferedOutputStream outBuf = new BufferedOutputStream(out);
			try {
				byte[] bytes = new byte[inBuf.available()];
				inBuf.read(bytes);
				if (JpcapTools.IS_WIFI_CHIP_VENDOR_BRCM == true) {
					Log.d(JpcapTools.TAG, "JpcapTools.IS_WIFI_CHIP_VENDOR_BRCM == true");
					bytes[DLT_IEEE802_11_TYPE_POSITION] = DLT_IEEE802_11_HEX;
				}
				outBuf.write(bytes);
			} catch (Exception e) {
			} finally {
				if (inBuf != null) inBuf.close();
				if (outBuf != null) outBuf.close();
				if (in != null) in.close();
				if (out != null) out.close();
			}
		}
	}
}
