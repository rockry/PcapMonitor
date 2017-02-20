package jpcap.packet.wlan;


import android.util.Log;
import jpcap.packet.wlan.frame.IWlanDataFrame;
import jpcap.packet.wlan.frame.IWlanManagementFrame;
import jpcap.packet.wlan.frame.control.inter.IClearToSendFrame;
import jpcap.packet.wlan.frame.control.inter.IContentionFreeFrame;
import jpcap.packet.wlan.frame.control.inter.IContentionFreeReceiveAckFrame;
import jpcap.packet.wlan.frame.control.inter.IPowerSavePollingFrame;
import jpcap.packet.wlan.frame.control.inter.IRequestToSendFrame;
import jpcap.packet.wlan.frame.control.inter.IackFrame;
import jpcap.packet.wlan.frame.data.inter.IDataFrame;
import jpcap.packet.wlan.frame.data.inter.INullFrame;
import jpcap.packet.wlan.frame.data.inter.IQosDataFrame;
import jpcap.packet.wlan.frame.management.DisassociationFrame;
import jpcap.packet.wlan.frame.management.element.IWlanElement;
import jpcap.packet.wlan.frame.management.element.inter.IDsssParameterSetElement;
import jpcap.packet.wlan.frame.management.element.inter.IErpElement;
import jpcap.packet.wlan.frame.management.element.inter.IExtendedSupportedRateElement;
import jpcap.packet.wlan.frame.management.element.inter.IHtCapabilitiesElement;
import jpcap.packet.wlan.frame.management.element.inter.ISsidElement;
import jpcap.packet.wlan.frame.management.element.inter.ISupportedRateElement;
import jpcap.packet.wlan.frame.management.element.inter.ITimElement;
import jpcap.packet.wlan.frame.management.inter.IAssociationRequestFrame;
import jpcap.packet.wlan.frame.management.inter.IAssociationResponseFrame;
import jpcap.packet.wlan.frame.management.inter.IAuthenticationFrame;
import jpcap.packet.wlan.frame.management.inter.IBeaconFrame;
import jpcap.packet.wlan.frame.management.inter.IDeauthenticationFrame;
import jpcap.packet.wlan.frame.management.inter.IProbeRequestFrame;
import jpcap.packet.wlan.frame.management.inter.IProbeResponseFrame;
import jpcap.packet.wlan.frame.management.inter.IReassociationRequestFrame;
import jpcap.packet.wlan.frame.management.inter.IReassociationResponseFrame;
import jpcap.packet.wlan.frame.management.inter.IibssAnnoucementIndicationMapFrame;
import jpcap.packet.wlan.inter.IWlan802dot11Radiotap;
import jpcap.packet.wlan.inter.IWlanControlFrame;
import jpcap.packet.wlan.utils.ByteUtils;
import pcapmonitor.JpcapTools;


public class DisplayDecodingInfo {

	private final static String tab ="----";
	
	/**
	 * Display all information about Wlan802dot11 frames
	 * 
	 * @param wlanDecodedFrameList
	 */
	public static void displayAllInfo(IWlan802dot11Radiotap wlan802dot11Radiotap)
	{

		Log.d(JpcapTools.TAG, "Wlan frame control");

		Log.d(JpcapTools.TAG, tab + "protocolVersion   : "
				+ (wlan802dot11Radiotap.getFrameControl().getProtocolVersion() & 0xFF));
		Log.d(JpcapTools.TAG, 
				tab + "type              : " + (wlan802dot11Radiotap.getFrameControl().getType() & 0xFF));
		Log.d(JpcapTools.TAG, 
				tab + "subType           : " + (wlan802dot11Radiotap.getFrameControl().getSubType() & 0xFF));
		Log.d(JpcapTools.TAG, tab + "toDS              : " + wlan802dot11Radiotap.getFrameControl().isToDS());
		Log.d(JpcapTools.TAG, tab + "fromDS            : " + wlan802dot11Radiotap.getFrameControl().isFromDS());
		Log.d(JpcapTools.TAG, 
				tab + "moreFragmentation : " + wlan802dot11Radiotap.getFrameControl().isMoreFragmentation());
		Log.d(JpcapTools.TAG, tab + "retry             : " + wlan802dot11Radiotap.getFrameControl().isRetry());
		Log.d(JpcapTools.TAG, 
				tab + "powerManagement   : " + wlan802dot11Radiotap.getFrameControl().isPowerManagement());
		Log.d(JpcapTools.TAG, tab + "moreData          : " + wlan802dot11Radiotap.getFrameControl().isMoreData());
		Log.d(JpcapTools.TAG, tab + "wep               : " + wlan802dot11Radiotap.getFrameControl().isWep());
		Log.d(JpcapTools.TAG, tab + "order             : " + wlan802dot11Radiotap.getFrameControl().isOrder());

		if (wlan802dot11Radiotap.getFrame() instanceof IWlanManagementFrame) {
			Log.d(JpcapTools.TAG, "Wlan management frame");
			IWlanManagementFrame managementFrame = (IWlanManagementFrame) wlan802dot11Radiotap.getFrame();

			Log.d(JpcapTools.TAG, tab + "duration id     : "
					+ ByteUtils.byteArrayToStringMessage("", managementFrame.getDurationId(), '|'));
			Log.d(JpcapTools.TAG, tab + "destinationAddr : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getDestinationAddr(), ':'));
			Log.d(JpcapTools.TAG, tab + "sourceAddr      : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getSourceAddr(), ':'));
			Log.d(JpcapTools.TAG, tab + "bssid           : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getBSSID(), ':'));
			Log.d(JpcapTools.TAG, tab + "sequenceControl : "
					+ ByteUtils.byteArrayToStringMessage("", managementFrame.getSequenceControl(), '|'));
			Log.d(JpcapTools.TAG, tab + "frameBody       : "
					+ ByteUtils.byteArrayToStringMessage("", managementFrame.getFrameBody(), '|'));
			Log.d(JpcapTools.TAG, 
					tab + "fcs             : " + ByteUtils.byteArrayToStringMessage("", managementFrame.getFcs(), '|'));

			if (wlan802dot11Radiotap.getFrame() instanceof IAssociationRequestFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT ASSOCIATION REQUEST FRAME");

				IAssociationRequestFrame associationRequestFrame = (IAssociationRequestFrame) wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + tab + "listenInterval         : "
						+ ByteUtils.byteArrayToStringMessage("", associationRequestFrame.getListenInterval(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", associationRequestFrame.getCapabilityInfo(), '|'));

				for (int j = 0; j < associationRequestFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(associationRequestFrame.getTaggedParameter().get(j));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IAssociationResponseFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT ASSOCATION RESPONSE FRAME");

				IAssociationResponseFrame associationFrame = (IAssociationResponseFrame) wlan802dot11Radiotap
						.getFrame();

				Log.d(JpcapTools.TAG, tab + tab + "statusCode             : " + associationFrame.getStatusCode());
				Log.d(JpcapTools.TAG, tab + tab + "associationId          : " + associationFrame.getAssociationId());
				Log.d(JpcapTools.TAG, tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", associationFrame.getCapabilityInfo(), '|'));

				for (int j = 0; j < associationFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(associationFrame.getTaggedParameter().get(j));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IAuthenticationFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT AUTHENTICATION FRAME");

				IAuthenticationFrame authenticationFrame = (IAuthenticationFrame) wlan802dot11Radiotap
						.getFrame();

				Log.d(JpcapTools.TAG, tab + tab + "authenticationAlgorithmNum : "
						+ authenticationFrame.getAuthenticationAlgorithmNum());
				Log.d(JpcapTools.TAG, 
						tab + tab + "authenticationSeqNum       : " + authenticationFrame.getAuthenticationSeqNum());
				Log.d(JpcapTools.TAG, tab + tab + "statusCode                 : " + authenticationFrame.getStatusCode());
			} else if (wlan802dot11Radiotap.getFrame() instanceof IBeaconFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT BEACON FRAME");

				IBeaconFrame beaconFrame = (IBeaconFrame) wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + tab + "timestamp              : "
						+ ByteUtils.byteArrayToStringMessage("", beaconFrame.getTimestamp()));
				Log.d(JpcapTools.TAG, tab + tab + "beaconInterval         : "
						+ ByteUtils.convertByteArrayToInt(beaconFrame.getBeaconInterval()));
				Log.d(JpcapTools.TAG, tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", beaconFrame.getCapabilityInfo(), '|'));

				for (int j = 0; j < beaconFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(beaconFrame.getTaggedParameter().get(j));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IDeauthenticationFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT DEAUTHENTICATION FRAME");

				Log.d(JpcapTools.TAG, tab + tab + "reasonCode : "
						+ ((IDeauthenticationFrame) wlan802dot11Radiotap.getFrame()).getReasonCode());
			} else if (wlan802dot11Radiotap.getFrame() instanceof DisassociationFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT DISASSOCIATION FRAME");

				Log.d(JpcapTools.TAG, tab + tab + "statusCode : "
						+ ((DisassociationFrame) wlan802dot11Radiotap.getFrame()).getStatusCode());
			} else if (wlan802dot11Radiotap.getFrame() instanceof IibssAnnoucementIndicationMapFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT IBSS ANNOUCEMENT INDICATION MAP FRAME");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IProbeRequestFrame) {
				Log.d(JpcapTools.TAG, tab + "MANAGEMENT - PROBE REQUEST FRAME");
				IProbeRequestFrame probeFrame = (IProbeRequestFrame) wlan802dot11Radiotap.getFrame();

				for (int j = 0; j < probeFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(probeFrame.getTaggedParameter().get(j));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IProbeResponseFrame) {
				IProbeResponseFrame probeFrame = (IProbeResponseFrame) wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + "MANAGEMENT - PROBE RESPONSE FRAME");
				Log.d(JpcapTools.TAG, tab + tab + "timestamp              : "
						+ ByteUtils.byteArrayToStringMessage("", probeFrame.getTimestamp()));
				Log.d(JpcapTools.TAG, tab + tab + "beaconInterval         : "
						+ ByteUtils.convertByteArrayToInt(probeFrame.getBeaconInterval()));
				Log.d(JpcapTools.TAG, tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", probeFrame.getCapabilityInformation(), '|'));

				for (int j = 0; j < probeFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(probeFrame.getTaggedParameter().get(j));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IReassociationRequestFrame) {
				IReassociationRequestFrame reassociationFrame = (IReassociationRequestFrame) wlan802dot11Radiotap
						.getFrame();

				Log.d(JpcapTools.TAG, tab + "MANAGEMENT REASSOCIATION FRAME");

				Log.d(JpcapTools.TAG, tab + tab + "listenInterval         : "
						+ ByteUtils.byteArrayToStringMessage("", reassociationFrame.getListenInterval(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "currentAPAdress        : "
						+ ByteUtils.convertByteArrayToInt(reassociationFrame.getCurrentAPAdress()));
				Log.d(JpcapTools.TAG, tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", reassociationFrame.getCapabilityInfo(), '|'));

				for (int j = 0; j < reassociationFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(reassociationFrame.getTaggedParameter().get(j));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IReassociationResponseFrame) {
				IReassociationResponseFrame reassociationFrame = (IReassociationResponseFrame)wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + "MANAGEMENT REASSOCATION RESPONSE FRAME");

				Log.d(JpcapTools.TAG, tab + tab + "statusCode             : " + reassociationFrame.getStatusCode());
				Log.d(JpcapTools.TAG, tab + tab + "associationId          : " + reassociationFrame.getAssociationId());
				Log.d(JpcapTools.TAG, tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", reassociationFrame.getCapabilityInfo(), '|'));

				for (int j = 0; j < reassociationFrame.getTaggedParameter().size(); j++) {
					displayTaggedParameter(reassociationFrame.getTaggedParameter().get(j));
				}
			}
		}
		if (wlan802dot11Radiotap.getFrame() instanceof IWlanDataFrame) {
			Log.d(JpcapTools.TAG, "Wlan data frame");
			IWlanDataFrame dataFrame = (IWlanDataFrame) wlan802dot11Radiotap.getFrame();

			Log.d(JpcapTools.TAG, tab + "duration id     : "
					+ ByteUtils.byteArrayToStringMessage("", dataFrame.getDurationId(), '|'));
			Log.d(JpcapTools.TAG, tab + "destinationAddr : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", dataFrame.getDestinationAddr(), ':'));
			Log.d(JpcapTools.TAG, tab + "sourceAddr      : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", dataFrame.getSourceAddr(), ':'));
			Log.d(JpcapTools.TAG, 
					tab + "bssid           : " + ByteUtils.byteArrayToStringMessage("", dataFrame.getBSSID(), ':'));
			Log.d(JpcapTools.TAG, tab + "sequenceControl : "
					+ ByteUtils.byteArrayToStringMessage("", dataFrame.getSequenceControl(), '|'));
			Log.d(JpcapTools.TAG, 
					tab + "frameBody       : " + ByteUtils.byteArrayToStringMessage("", dataFrame.getFrameBody(), '|'));

			if (wlan802dot11Radiotap.getFrame() instanceof IDataFrame)
				Log.d(JpcapTools.TAG, tab + "DATA FRAME");
			else if (wlan802dot11Radiotap.getFrame() instanceof INullFrame)
				Log.d(JpcapTools.TAG, tab + "NULL FRAME");
			else if (wlan802dot11Radiotap.getFrame() instanceof IQosDataFrame) {
				Log.d(JpcapTools.TAG, tab + "QOS DATA FRAME");
				Log.d(JpcapTools.TAG, tab + tab + "qos control : " + ByteUtils.byteArrayToStringMessage("",
						((IQosDataFrame) wlan802dot11Radiotap.getFrame()).getQosControl(), '|'));
			}
		}
		if (wlan802dot11Radiotap.getFrame() instanceof IWlanControlFrame) {

			Log.d(JpcapTools.TAG, "Wlan control frame");

			if (wlan802dot11Radiotap.getFrame() instanceof IackFrame) {
				IackFrame ackFrame = (IackFrame) wlan802dot11Radiotap.getFrame();
				Log.d(JpcapTools.TAG, tab + "CONTROL FRAME - ACK PACKET");
				Log.d(JpcapTools.TAG, tab + tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", ackFrame.getDurationId(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", ackFrame.getReceiverAddr(), ':'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IClearToSendFrame) {
				IClearToSendFrame cts = (IClearToSendFrame) wlan802dot11Radiotap.getFrame();
				Log.d(JpcapTools.TAG, tab + "CONTROL FRAME - CLEAR TO SEND PACKET");
				Log.d(JpcapTools.TAG, tab + tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", cts.getDurationId(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", cts.getReceiverAddr(), ':'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IContentionFreeFrame) {
				IContentionFreeFrame contentionFr = (IContentionFreeFrame) wlan802dot11Radiotap.getFrame();
				Log.d(JpcapTools.TAG, tab + "CONTROL FRAME - CONTENTION FREE PACKET");
				Log.d(JpcapTools.TAG, tab + tab + "duration id : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getDurationId(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getReceiverAddr(), ':'));
				Log.d(JpcapTools.TAG, tab + tab + "bss id       : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getBssid(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IContentionFreeReceiveAckFrame) {
				IContentionFreeReceiveAckFrame contentionFr = (IContentionFreeReceiveAckFrame) wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + "CONTROL FRAME - CONTENTION FREE AND RECEIVE ACK PACKET");
				Log.d(JpcapTools.TAG, tab + tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getDurationId(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getReceiverAddr(), ':'));
				Log.d(JpcapTools.TAG, tab + tab + "bss id       : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getBssid(), ':'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IPowerSavePollingFrame) {
				IPowerSavePollingFrame powerSave = (IPowerSavePollingFrame) wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + "CONTROL FRAME - POWER SAVE POLLING PACKET");
				Log.d(JpcapTools.TAG, tab + tab + "association id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getAssociationId(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "bss id         : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", powerSave.getBssid(), ':'));
				Log.d(JpcapTools.TAG, tab + tab + "transmitter id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getTransmitterId(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IRequestToSendFrame) {
				IRequestToSendFrame rts = (IRequestToSendFrame) wlan802dot11Radiotap.getFrame();

				Log.d(JpcapTools.TAG, tab + "CONTROL FRAME - REQUEST TO SEND PACKET");
				Log.d(JpcapTools.TAG, tab + tab + "duration id     : "
						+ ByteUtils.byteArrayToStringMessage("", rts.getDurationId(), '|'));
				Log.d(JpcapTools.TAG, tab + tab + "receiverAddr    : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", rts.getReceiverAddr(), ':'));
				Log.d(JpcapTools.TAG, tab + tab + "transmitterAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", rts.getTransmitterAddr(), ':'));
			}
		}

	}
	
	/**
	 * Display element information
	 * 
	 * @param elementList
	 * 		List of wlan element 
	 */
	public static void displayTaggedParameter(IWlanElement elementList)
	{
		Log.d(JpcapTools.TAG, tab+tab+tab + "Dynamic Elements");
		Log.d(JpcapTools.TAG, tab+tab+tab + "element id : "+ (elementList.getElementId() & 0xFF));
		
		if (elementList instanceof IDsssParameterSetElement)
		{
			IDsssParameterSetElement element = (IDsssParameterSetElement)elementList;
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"currentChannel : "+ element.getCurrentChannel());
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"frequency      : " + element.getFrequency());
		}
		else if (elementList instanceof IErpElement)
		{
			IErpElement element = (IErpElement)elementList;
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"isErpPresent         : " + element.isErpPresent());
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"useProtection        : " + element.useProtection());
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"isBarkerPreambleMode : " + element.isBarkerPreambleMode());
		}
		else if (elementList instanceof IExtendedSupportedRateElement)
		{
			IExtendedSupportedRateElement element = (IExtendedSupportedRateElement)elementList;
			String dataRateStr = "";
			for (int i = 0; i < element.getDataRate().length; i++) {
				dataRateStr += (((element.getDataRate()[i] & 0x7F)) / 2f) + ", ";
			}

			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"extended supported rates : " + dataRateStr.replace(".0", "")/* + " [Mbit/sec]"*/);
		}
		else if (elementList instanceof IHtCapabilitiesElement)
		{
			IHtCapabilitiesElement element = (IHtCapabilitiesElement)elementList;
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"support short 20Mhz           : "+ element.getHtCapabilityInfo().isSupportShortGi20Mhz());
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"support short 40Mhz           : "+ element.getHtCapabilityInfo().isSupportShortGi40Mhz());

			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"channel width 20MHz supported : "+ !element.getHtCapabilityInfo().isSupportedChannelWidthSet());
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"channel width 40MHz supported : "+ element.getHtCapabilityInfo().isSupportedChannelWidthSet());
			
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"AMPDU paramters               : "	+ (element.getAmpduParameters() & 0xFF));
			
			for (int i = 0; i < element.getSupportedMCSSet().getMcsList().size(); i++) {
				Log.d(JpcapTools.TAG, tab+tab+tab+tab+"MCS Supported : "+ element.getSupportedMCSSet().getMcsList().get(i).getMcsIndex() + "-"+ element.getSupportedMCSSet().getMcsList().get(i).getModulation());
			}
			
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"HT Extended capabilities : "+ ByteUtils.byteArrayToStringMessage("",element.getHtExtendedCapabilities(), '|'));
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"Beam forming capabilities : "+ ByteUtils.byteArrayToStringMessage("",element.getTransmitBeamformingCapabilities(), '|'));
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"ASEL capabilities : "+ (element.getAselCapabilities() & 0xFF));
		}
		else if (elementList instanceof ISsidElement)
		{
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"SSID : " +((ISsidElement)elementList).getSsid());
		}
		else if (elementList instanceof ISupportedRateElement)
		{
			ISupportedRateElement element = (ISupportedRateElement)elementList;
			String dataRateStr = "";
			
			for (int i = 0; i < element.getDataRate().length; i++) {
				dataRateStr += ((element.getDataRate()[i] & 0x7F) / 2f) + ", ";
			}

			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"supported rates : "+ dataRateStr.replace(".0", "")/* + " [Mbit/sec]"*/);
		}
		else if (elementList instanceof ITimElement)
		{
			ITimElement element = (ITimElement)elementList;
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"DTIM count  : "+ (element.getDTIMcount() & 0xFF));
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"DTIM period : "+ (element.getDTIMperiod() & 0XFF));
			Log.d(JpcapTools.TAG, tab+tab+tab+tab+"TIM bitmapControl : "+ (element.getBitmapControl() & 0XFF));
			Log.d(JpcapTools.TAG, ByteUtils.byteArrayToStringMessage(tab+tab+tab+tab+"TIM partialVirtualBitmap", element.getPartialVirtualBitmap(), '|'));;
		}
	}
	
	/**
	 * Display all information about Wlan802dot11 frames
	 * 
	 * @param wlanDecodedFrameList
	 */
	public static String getFrameInfo(IWlan802dot11Radiotap wlan802dot11Radiotap, boolean bShowFrameBody)
	{
		StringBuffer sb = new StringBuffer();
		sb.append("Wlan frame control\n");
		sb.append(tab + "protocolVersion   : "
				+ (wlan802dot11Radiotap.getFrameControl().getProtocolVersion() & 0xFF)); sb.append("\n");
		sb.append(
				tab + "type              : " + (wlan802dot11Radiotap.getFrameControl().getType() & 0xFF)); sb.append("\n");
		sb.append(
				tab + "subType           : " + (wlan802dot11Radiotap.getFrameControl().getSubType() & 0xFF)); sb.append("\n");
		sb.append(tab + "toDS              : " + wlan802dot11Radiotap.getFrameControl().isToDS()); sb.append("\n");
		sb.append(tab + "fromDS            : " + wlan802dot11Radiotap.getFrameControl().isFromDS()); sb.append("\n");
		sb.append(
				tab + "moreFragmentation : " + wlan802dot11Radiotap.getFrameControl().isMoreFragmentation()); sb.append("\n");
		sb.append(tab + "retry             : " + wlan802dot11Radiotap.getFrameControl().isRetry()); sb.append("\n");
		sb.append(
				tab + "powerManagement   : " + wlan802dot11Radiotap.getFrameControl().isPowerManagement()); sb.append("\n");
		sb.append(tab + "moreData          : " + wlan802dot11Radiotap.getFrameControl().isMoreData()); sb.append("\n");
		sb.append(tab + "wep               : " + wlan802dot11Radiotap.getFrameControl().isWep()); sb.append("\n");
		sb.append(tab + "order             : " + wlan802dot11Radiotap.getFrameControl().isOrder()); sb.append("\n");

		if (wlan802dot11Radiotap.getFrame() instanceof IWlanManagementFrame) {
			sb.append("Wlan management frame"); sb.append("\n");
			IWlanManagementFrame managementFrame = (IWlanManagementFrame) wlan802dot11Radiotap.getFrame();

			sb.append(tab + "duration id     : "
					+ ByteUtils.byteArrayToStringMessage("", managementFrame.getDurationId(), '|')); sb.append("\n");
			sb.append(tab + "destinationAddr : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getDestinationAddr(), ':')); sb.append("\n");
			sb.append(tab + "sourceAddr      : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getSourceAddr(), ':')); sb.append("\n");
			sb.append(tab + "bssid           : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", managementFrame.getBSSID(), ':')); sb.append("\n");
			sb.append(tab + "sequenceControl : "
					+ ByteUtils.byteArrayToStringMessage("", managementFrame.getSequenceControl(), '|')); sb.append("\n");
			if (bShowFrameBody == true) {		
				sb.append(tab + "frameBody       : "
						+ ByteUtils.byteArrayToStringMessage("", managementFrame.getFrameBody(), '|')); sb.append("\n");
			} else {
				sb.append(tab + "frameBody       : +"); sb.append("\n");				
			}
			sb.append(
					tab + "fcs             : " + ByteUtils.byteArrayToStringMessage("", managementFrame.getFcs(), '|')); sb.append("\n");

			if (wlan802dot11Radiotap.getFrame() instanceof IAssociationRequestFrame) {
				sb.append(tab + "MANAGEMENT ASSOCIATION REQUEST FRAME"); sb.append("\n");

				IAssociationRequestFrame associationRequestFrame = (IAssociationRequestFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + tab + "listenInterval         : "
						+ ByteUtils.byteArrayToStringMessage("", associationRequestFrame.getListenInterval(), '|')); sb.append("\n");
				sb.append(tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", associationRequestFrame.getCapabilityInfo(), '|')); sb.append("\n");

				for (int j = 0; j < associationRequestFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(associationRequestFrame.getTaggedParameter().get(j)));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IAssociationResponseFrame) {
				sb.append(tab + "MANAGEMENT ASSOCATION RESPONSE FRAME"); sb.append("\n");

				IAssociationResponseFrame associationFrame = (IAssociationResponseFrame) wlan802dot11Radiotap
						.getFrame();

				sb.append(tab + tab + "statusCode             : " + associationFrame.getStatusCode()); sb.append("\n");
				sb.append(tab + tab + "associationId          : " + associationFrame.getAssociationId()); sb.append("\n");
				sb.append(tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", associationFrame.getCapabilityInfo(), '|')); sb.append("\n");

				for (int j = 0; j < associationFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(associationFrame.getTaggedParameter().get(j)));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IAuthenticationFrame) {
				sb.append(tab + "MANAGEMENT AUTHENTICATION FRAME"); sb.append("\n");

				IAuthenticationFrame authenticationFrame = (IAuthenticationFrame) wlan802dot11Radiotap
						.getFrame();

				sb.append(tab + tab + "authenticationAlgorithmNum : "
						+ authenticationFrame.getAuthenticationAlgorithmNum()); sb.append("\n");
				sb.append(
						tab + tab + "authenticationSeqNum       : " + authenticationFrame.getAuthenticationSeqNum()); sb.append("\n");
				sb.append(tab + tab + "statusCode                 : " + authenticationFrame.getStatusCode()); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IBeaconFrame) {
				sb.append(tab + "MANAGEMENT BEACON FRAME"); sb.append("\n");

				IBeaconFrame beaconFrame = (IBeaconFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + tab + "timestamp              : "
						+ ByteUtils.byteArrayToStringMessage("", beaconFrame.getTimestamp())); sb.append("\n");
				sb.append(tab + tab + "beaconInterval         : "
						+ ByteUtils.convertByteArrayToInt(beaconFrame.getBeaconInterval())); sb.append("\n");
				sb.append(tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", beaconFrame.getCapabilityInfo(), '|')); sb.append("\n");

				for (int j = 0; j < beaconFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(beaconFrame.getTaggedParameter().get(j)));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IDeauthenticationFrame) {
				sb.append(tab + "MANAGEMENT DEAUTHENTICATION FRAME"); sb.append("\n");

				sb.append(tab + tab + "reasonCode : "
						+ ((IDeauthenticationFrame) wlan802dot11Radiotap.getFrame()).getReasonCode()); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof DisassociationFrame) {
				sb.append(tab + "MANAGEMENT DISASSOCIATION FRAME"); sb.append("\n");

				sb.append(tab + tab + "statusCode : "
						+ ((DisassociationFrame) wlan802dot11Radiotap.getFrame()).getStatusCode()); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IibssAnnoucementIndicationMapFrame) {
				sb.append(tab + "MANAGEMENT IBSS ANNOUCEMENT INDICATION MAP FRAME"); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IProbeRequestFrame) {
				sb.append(tab + "MANAGEMENT - PROBE REQUEST FRAME"); sb.append("\n");
				IProbeRequestFrame probeFrame = (IProbeRequestFrame) wlan802dot11Radiotap.getFrame();

				for (int j = 0; j < probeFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(probeFrame.getTaggedParameter().get(j)));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IProbeResponseFrame) {
				IProbeResponseFrame probeFrame = (IProbeResponseFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + "MANAGEMENT - PROBE RESPONSE FRAME"); sb.append("\n");
				sb.append(tab + tab + "timestamp              : "
						+ ByteUtils.byteArrayToStringMessage("", probeFrame.getTimestamp())); sb.append("\n");
				sb.append(tab + tab + "beaconInterval         : "
						+ ByteUtils.convertByteArrayToInt(probeFrame.getBeaconInterval())); sb.append("\n");
				sb.append(tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", probeFrame.getCapabilityInformation(), '|')); sb.append("\n");

				for (int j = 0; j < probeFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(probeFrame.getTaggedParameter().get(j))); 
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IReassociationRequestFrame) {
				IReassociationRequestFrame reassociationFrame = (IReassociationRequestFrame) wlan802dot11Radiotap
						.getFrame();

				sb.append(tab + "MANAGEMENT REASSOCIATION FRAME"); sb.append("\n");

				sb.append(tab + tab + "listenInterval         : "
						+ ByteUtils.byteArrayToStringMessage("", reassociationFrame.getListenInterval(), '|')); sb.append("\n");
				sb.append(tab + tab + "currentAPAdress        : "
						+ ByteUtils.convertByteArrayToInt(reassociationFrame.getCurrentAPAdress())); sb.append("\n");
				sb.append(tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", reassociationFrame.getCapabilityInfo(), '|')); sb.append("\n");

				for (int j = 0; j < reassociationFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(reassociationFrame.getTaggedParameter().get(j)));
				}
			} else if (wlan802dot11Radiotap.getFrame() instanceof IReassociationResponseFrame) {
				IReassociationResponseFrame reassociationFrame = (IReassociationResponseFrame)wlan802dot11Radiotap.getFrame();

				sb.append(tab + "MANAGEMENT REASSOCATION RESPONSE FRAME"); sb.append("\n");

				sb.append(tab + tab + "statusCode             : " + reassociationFrame.getStatusCode()); sb.append("\n");
				sb.append(tab + tab + "associationId          : " + reassociationFrame.getAssociationId()); sb.append("\n");
				sb.append(tab + tab + "capability information : "
						+ ByteUtils.byteArrayToStringMessage("", reassociationFrame.getCapabilityInfo(), '|')); sb.append("\n");

				for (int j = 0; j < reassociationFrame.getTaggedParameter().size(); j++) {
					sb.append(getElementTaggedParameter(reassociationFrame.getTaggedParameter().get(j)));
				}
			}
		}
		if (wlan802dot11Radiotap.getFrame() instanceof IWlanDataFrame) {
			sb.append("Wlan data frame"); sb.append("\n");
			IWlanDataFrame dataFrame = (IWlanDataFrame) wlan802dot11Radiotap.getFrame();

			sb.append(tab + "duration id     : "
					+ ByteUtils.byteArrayToStringMessage("", dataFrame.getDurationId(), '|')); sb.append("\n");
			sb.append(tab + "destinationAddr : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", dataFrame.getDestinationAddr(), ':')); sb.append("\n");
			sb.append(tab + "sourceAddr      : "
					+ ByteUtils.byteArrayToStringMessageNoSpace("", dataFrame.getSourceAddr(), ':')); sb.append("\n");
			sb.append(
					tab + "bssid           : " + ByteUtils.byteArrayToStringMessage("", dataFrame.getBSSID(), '|')); sb.append("\n");
			sb.append(tab + "sequenceControl : "
					+ ByteUtils.byteArrayToStringMessage("", dataFrame.getSequenceControl(), '|')); sb.append("\n");
					
			if (bShowFrameBody == true) {		
				sb.append(
						tab + "frameBody       : " + ByteUtils.byteArrayToStringMessage("", dataFrame.getFrameBody(), '|')); sb.append("\n");
			} else {
				sb.append(
						tab + "frameBody       : +"); sb.append("\n");
			}
			
			if (wlan802dot11Radiotap.getFrame() instanceof IDataFrame) {
				sb.append(tab + "DATA FRAME"); sb.append("\n");
			}
			else if (wlan802dot11Radiotap.getFrame() instanceof INullFrame) {
				sb.append(tab + "NULL FRAME"); sb.append("\n");
			}
			else if (wlan802dot11Radiotap.getFrame() instanceof IQosDataFrame) {
				sb.append(tab + "QOS DATA FRAME"); sb.append("\n");
				sb.append(tab + tab + "qos control : " + ByteUtils.byteArrayToStringMessage("",
						((IQosDataFrame) wlan802dot11Radiotap.getFrame()).getQosControl(), '|')); sb.append("\n");
			}
		}
		if (wlan802dot11Radiotap.getFrame() instanceof IWlanControlFrame) {

			sb.append("Wlan control frame"); sb.append("\n");

			if (wlan802dot11Radiotap.getFrame() instanceof IackFrame) {
				IackFrame ackFrame = (IackFrame) wlan802dot11Radiotap.getFrame();
				sb.append(tab + "CONTROL FRAME - ACK PACKET"); sb.append("\n");
				sb.append(tab + tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", ackFrame.getDurationId(), '|')); sb.append("\n");
				sb.append(tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", ackFrame.getReceiverAddr(), ':')); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IClearToSendFrame) {
				IClearToSendFrame cts = (IClearToSendFrame) wlan802dot11Radiotap.getFrame();
				sb.append(tab + "CONTROL FRAME - CLEAR TO SEND PACKET"); sb.append("\n");
				sb.append(tab + tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", cts.getDurationId(), '|')); sb.append("\n");
				sb.append(tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", cts.getReceiverAddr(), ':')); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IContentionFreeFrame) {
				IContentionFreeFrame contentionFr = (IContentionFreeFrame) wlan802dot11Radiotap.getFrame();
				sb.append(tab + "CONTROL FRAME - CONTENTION FREE PACKET"); sb.append("\n");
				sb.append(tab + tab + "duration id : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getDurationId(), '|')); sb.append("\n");
				sb.append(tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getReceiverAddr(), ':')); sb.append("\n");
				sb.append(tab + tab + "bss id       : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getBssid(), ':')); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IContentionFreeReceiveAckFrame) {
				IContentionFreeReceiveAckFrame contentionFr = (IContentionFreeReceiveAckFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + "CONTROL FRAME - CONTENTION FREE AND RECEIVE ACK PACKET"); sb.append("\n");
				sb.append(tab + tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getDurationId(), '|')); sb.append("\n");
				sb.append(tab + tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getReceiverAddr(), ':')); sb.append("\n");
				sb.append(tab + tab + "bss id       : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", contentionFr.getBssid(), ':')); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IPowerSavePollingFrame) {
				IPowerSavePollingFrame powerSave = (IPowerSavePollingFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + "CONTROL FRAME - POWER SAVE POLLING PACKET"); sb.append("\n");
				sb.append(tab + tab + "association id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getAssociationId(), '|')); sb.append("\n");
				sb.append(tab + tab + "bss id         : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getBssid(), '|')); sb.append("\n");
				sb.append(tab + tab + "transmitter id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getTransmitterId(), '|')); sb.append("\n");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IRequestToSendFrame) {
				IRequestToSendFrame rts = (IRequestToSendFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + "CONTROL FRAME - REQUEST TO SEND PACKET"); sb.append("\n");
				sb.append(tab + tab + "duration id     : "
						+ ByteUtils.byteArrayToStringMessage("", rts.getDurationId(), '|')); sb.append("\n");
				sb.append(tab + tab + "receiverAddr    : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", rts.getReceiverAddr(), ':')); sb.append("\n");
				sb.append(tab + tab + "transmitterAddr : "
						+ ByteUtils.byteArrayToStringMessageNoSpace("", rts.getTransmitterAddr(), ':')); sb.append("\n");
			}
		}

		return sb.toString();
	}
	
	/**
	 * Display all information about Wlan802dot11 frames without frame body
	 * 
	 * @param wlanDecodedFrameList
	 */
	public static String getMainInfo(IWlan802dot11Radiotap wlan802dot11Radiotap)
	{
		return getFrameInfo(wlan802dot11Radiotap, false);
	}

	/**
	 * Display all information about Wlan802dot11 frames without frame body
	 * 
	 * @param wlanDecodedFrameList
	 */
	public static String getSummaryInfo(IWlan802dot11Radiotap wlan802dot11Radiotap) {
		StringBuffer sb = new StringBuffer();
		if (wlan802dot11Radiotap.getFrame() instanceof IAssociationRequestFrame) {
			sb.append(tab + "MANAGEMENT ASSOCIATION REQUEST FRAME");
		} else if (wlan802dot11Radiotap.getFrame() instanceof IAssociationResponseFrame) {
			sb.append(tab + "MANAGEMENT ASSOCATION RESPONSE FRAME");
			IAssociationResponseFrame associationFrame = (IAssociationResponseFrame) wlan802dot11Radiotap.getFrame();

			sb.append(tab + "statusCode : " + associationFrame.getStatusCode());
			sb.append(tab + "associationId : " + associationFrame.getAssociationId());
		} else if (wlan802dot11Radiotap.getFrame() instanceof IAuthenticationFrame) {
			sb.append(tab + "MANAGEMENT AUTHENTICATION FRAME");
			IAuthenticationFrame authenticationFrame = (IAuthenticationFrame) wlan802dot11Radiotap.getFrame();
			sb.append(tab + "authenticationAlgorithmNum : " + authenticationFrame.getAuthenticationAlgorithmNum());
			sb.append(tab + "statusCode : " + authenticationFrame.getStatusCode());
		} else if (wlan802dot11Radiotap.getFrame() instanceof IBeaconFrame) {
			sb.append(tab + "MANAGEMENT BEACON FRAME ");

			IBeaconFrame beaconFrame = (IBeaconFrame) wlan802dot11Radiotap.getFrame();
			sb.append(tab + "beaconInterval : " + ByteUtils.convertByteArrayToInt(beaconFrame.getBeaconInterval()));
		} else if (wlan802dot11Radiotap.getFrame() instanceof IDeauthenticationFrame) {
			sb.append(tab + "MANAGEMENT DEAUTHENTICATION FRAME");
			sb.append(tab + "reasonCode : "
					+ ((IDeauthenticationFrame) wlan802dot11Radiotap.getFrame()).getReasonCode());
		} else if (wlan802dot11Radiotap.getFrame() instanceof DisassociationFrame) {
			sb.append(tab + "MANAGEMENT DISASSOCIATION FRAME");
			sb.append(tab + "statusCode : "
					+ ((DisassociationFrame) wlan802dot11Radiotap.getFrame()).getStatusCode());
		} else if (wlan802dot11Radiotap.getFrame() instanceof IibssAnnoucementIndicationMapFrame) {
			sb.append(tab + "MANAGEMENT IBSS ANNOUCEMENT INDICATION MAP FRAME");
		} else if (wlan802dot11Radiotap.getFrame() instanceof IProbeRequestFrame) {
			sb.append(tab + "MANAGEMENT - PROBE REQUEST FRAME");
		} else if (wlan802dot11Radiotap.getFrame() instanceof IProbeResponseFrame) {
			IProbeResponseFrame probeFrame = (IProbeResponseFrame) wlan802dot11Radiotap.getFrame();

			sb.append(tab + "MANAGEMENT - PROBE RESPONSE FRAME");
			sb.append(tab + "beaconInterval : "
					+ ByteUtils.convertByteArrayToInt(probeFrame.getBeaconInterval()));
		} else if (wlan802dot11Radiotap.getFrame() instanceof IReassociationRequestFrame) {
			IReassociationRequestFrame reassociationFrame = (IReassociationRequestFrame) wlan802dot11Radiotap
					.getFrame();

			sb.append(tab + "MANAGEMENT REASSOCIATION FRAME");
			sb.append(tab + "currentAPAdress : "
					+ ByteUtils.convertByteArrayToInt(reassociationFrame.getCurrentAPAdress()));
		} else if (wlan802dot11Radiotap.getFrame() instanceof IReassociationResponseFrame) {
			IReassociationResponseFrame reassociationFrame = (IReassociationResponseFrame) wlan802dot11Radiotap
					.getFrame();

			sb.append(tab + "MANAGEMENT REASSOCATION RESPONSE FRAME");
			sb.append(tab + "associationId : " + reassociationFrame.getAssociationId());
		}

		if (wlan802dot11Radiotap.getFrame() instanceof IWlanDataFrame) {
			sb.append("Wlan data frame");
			IWlanDataFrame dataFrame = (IWlanDataFrame) wlan802dot11Radiotap.getFrame();
			sb.append(tab + "destinationAddr : "
					+ ByteUtils.byteArrayToStringMessage("", dataFrame.getDestinationAddr(), '|'));
			sb.append(tab + "sourceAddr : "
					+ ByteUtils.byteArrayToStringMessage("", dataFrame.getSourceAddr(), '|'));

			if (wlan802dot11Radiotap.getFrame() instanceof IDataFrame) {
				sb.append(tab + "DATA FRAME");
			} else if (wlan802dot11Radiotap.getFrame() instanceof INullFrame) {
				sb.append(tab + "NULL FRAME");
			} else if (wlan802dot11Radiotap.getFrame() instanceof IQosDataFrame) {
				sb.append(tab + "QOS DATA FRAME");
				sb.append(tab + "qos control : " + ByteUtils.byteArrayToStringMessage("",
						((IQosDataFrame) wlan802dot11Radiotap.getFrame()).getQosControl(), '|'));
			}
		}
		if (wlan802dot11Radiotap.getFrame() instanceof IWlanControlFrame) {
			if (wlan802dot11Radiotap.getFrame() instanceof IackFrame) {
				IackFrame ackFrame = (IackFrame) wlan802dot11Radiotap.getFrame();
				sb.append(tab + "CONTROL FRAME - ACK PACKET");
				sb.append(tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", ackFrame.getDurationId(), '|'));
				sb.append(tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessage("", ackFrame.getReceiverAddr(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IClearToSendFrame) {
				IClearToSendFrame cts = (IClearToSendFrame) wlan802dot11Radiotap.getFrame();
				sb.append(tab + "CONTROL FRAME - CLEAR TO SEND PACKET");
				sb.append(tab + "duration id  : "
						+ ByteUtils.byteArrayToStringMessage("", cts.getDurationId(), '|'));
				sb.append(tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessage("", cts.getReceiverAddr(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IContentionFreeFrame) {
				IContentionFreeFrame contentionFr = (IContentionFreeFrame) wlan802dot11Radiotap.getFrame();
				sb.append(tab + "CONTROL FRAME - CONTENTION FREE PACKET");
				sb.append(tab + "duration id : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getDurationId(), '|'));
				sb.append(tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getReceiverAddr(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IContentionFreeReceiveAckFrame) {
				IContentionFreeReceiveAckFrame contentionFr = (IContentionFreeReceiveAckFrame) wlan802dot11Radiotap
						.getFrame();

				sb.append(tab + "CONTROL FRAME - CONTENTION FREE AND RECEIVE ACK PACKET");
				sb.append(tab + "duration id : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getDurationId(), '|'));
				sb.append(tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessage("", contentionFr.getReceiverAddr(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IPowerSavePollingFrame) {
				IPowerSavePollingFrame powerSave = (IPowerSavePollingFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + "CONTROL FRAME - POWER SAVE POLLING PACKET");
				sb.append(tab + "association id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getAssociationId(), '|'));
				sb.append(tab + "bss id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getBssid(), '|'));
				sb.append(tab + "transmitter id : "
						+ ByteUtils.byteArrayToStringMessage("", powerSave.getTransmitterId(), '|'));
			} else if (wlan802dot11Radiotap.getFrame() instanceof IRequestToSendFrame) {
				IRequestToSendFrame rts = (IRequestToSendFrame) wlan802dot11Radiotap.getFrame();

				sb.append(tab + "CONTROL FRAME - REQUEST TO SEND PACKET");
				sb.append(tab + "duration id : "
						+ ByteUtils.byteArrayToStringMessage("", rts.getDurationId(), '|'));
				sb.append(tab + "receiverAddr : "
						+ ByteUtils.byteArrayToStringMessage("", rts.getReceiverAddr(), '|'));
				sb.append(tab + "transmitterAddr : "
						+ ByteUtils.byteArrayToStringMessage("", rts.getTransmitterAddr(), '|'));
			}
		}

		return sb.toString();
	}

	/**
	 * Display all information about Wlan802dot11 frames
	 * 
	 * @param wlanDecodedFrameList
	 */
	public static String getAllInfo(IWlan802dot11Radiotap wlan802dot11Radiotap)
	{
		return getFrameInfo(wlan802dot11Radiotap, true);
	}
	
	/**
	 * get element information
	 * 
	 * @param elementList
	 * 		List of wlan element 
	 */
	public static String getElementTaggedParameter(IWlanElement elementList)
	{
		StringBuffer sb = new StringBuffer();
		
		sb.append(tab+tab+tab + "Dynamic Elements"); sb.append("\n");
		sb.append(tab+tab+tab + "element id : "+ (elementList.getElementId() & 0xFF)); sb.append("\n");
		
		if (elementList instanceof IDsssParameterSetElement)
		{
			IDsssParameterSetElement element = (IDsssParameterSetElement)elementList;
			sb.append(tab+tab+tab+tab+"currentChannel : "+ element.getCurrentChannel()); sb.append("\n");
			sb.append(tab+tab+tab+tab+"frequency      : " + element.getFrequency()); sb.append("\n");
		}
		else if (elementList instanceof IErpElement)
		{
			IErpElement element = (IErpElement)elementList;
			sb.append(tab+tab+tab+tab+"isErpPresent         : " + element.isErpPresent()); sb.append("\n");
			sb.append(tab+tab+tab+tab+"useProtection        : " + element.useProtection()); sb.append("\n");
			sb.append(tab+tab+tab+tab+"isBarkerPreambleMode : " + element.isBarkerPreambleMode()); sb.append("\n");
		}
		else if (elementList instanceof IExtendedSupportedRateElement)
		{
			IExtendedSupportedRateElement element = (IExtendedSupportedRateElement)elementList;
			String dataRateStr = "";
			for (int i = 0; i < element.getDataRate().length; i++) {
				dataRateStr += (((element.getDataRate()[i] & 0x7F)) / 2f) + ", ";
			}

			sb.append(tab+tab+tab+tab+"extended supported rate: " + dataRateStr.replace(".0", "")/* + " [Mbit/sec]"*/); sb.append("\n");
		}
		else if (elementList instanceof IHtCapabilitiesElement)
		{
			IHtCapabilitiesElement element = (IHtCapabilitiesElement)elementList;
			sb.append(tab+tab+tab+tab+"support short 20Mhz           : "+ element.getHtCapabilityInfo().isSupportShortGi20Mhz()); sb.append("\n");
			sb.append(tab+tab+tab+tab+"support short 40Mhz           : "+ element.getHtCapabilityInfo().isSupportShortGi40Mhz()); sb.append("\n");

			sb.append(tab+tab+tab+tab+"channel width 20MHz supported : "+ !element.getHtCapabilityInfo().isSupportedChannelWidthSet()); sb.append("\n");
			sb.append(tab+tab+tab+tab+"channel width 40MHz supported : "+ element.getHtCapabilityInfo().isSupportedChannelWidthSet()); sb.append("\n");
			
			sb.append(tab+tab+tab+tab+"AMPDU paramters               : "	+ (element.getAmpduParameters() & 0xFF)); sb.append("\n");
			
			for (int i = 0; i < element.getSupportedMCSSet().getMcsList().size(); i++) {
				sb.append(tab+tab+tab+tab+"MCS Supported : "+ element.getSupportedMCSSet().getMcsList().get(i).getMcsIndex() + "-"+ element.getSupportedMCSSet().getMcsList().get(i).getModulation()); sb.append("\n");
			}
			
			sb.append(tab+tab+tab+tab+"HT Extended capabilities : "+ ByteUtils.byteArrayToStringMessage("",element.getHtExtendedCapabilities(), '|')); sb.append("\n");
			sb.append(tab+tab+tab+tab+"Beam forming capabilities : "+ ByteUtils.byteArrayToStringMessage("",element.getTransmitBeamformingCapabilities(), '|')); sb.append("\n");
			sb.append(tab+tab+tab+tab+"ASEL capabilities : "+ (element.getAselCapabilities() & 0xFF)); sb.append("\n");
		}
		else if (elementList instanceof ISsidElement)
		{
			sb.append(tab+tab+tab+tab+"SSID : " +((ISsidElement)elementList).getSsid()); sb.append("\n");
		}
		else if (elementList instanceof ISupportedRateElement)
		{
			ISupportedRateElement element = (ISupportedRateElement)elementList;
			String dataRateStr = "";
			
			for (int i = 0; i < element.getDataRate().length; i++) {
				dataRateStr += (((element.getDataRate()[i] & 0x7F)) / 2f) + ", ";
			}
			sb.append(tab+tab+tab+tab+"supported rates : "+ dataRateStr.replace(".0", "")/* + " [Mbit/sec]"*/); sb.append("\n");
		}
		else if (elementList instanceof ITimElement)
		{
			ITimElement element = (ITimElement)elementList;
			sb.append(tab+tab+tab+tab+"DTIM count  : "+ (element.getDTIMcount() & 0xFF)); sb.append("\n");
			sb.append(tab+tab+tab+tab+"DTIM period : "+ (element.getDTIMperiod() & 0XFF)); sb.append("\n");
			sb.append(tab+tab+tab+tab+"TIM bitmapControl : "+ (element.getBitmapControl() & 0XFF)); sb.append("\n");
			sb.append(ByteUtils.byteArrayToStringMessage(tab+tab+tab+tab+"TIM partialVirtualBitmap", element.getPartialVirtualBitmap(), '|')); sb.append("\n");
		}
		
		return sb.toString();
	}
	
	/**
	 * get element information - SSID
	 * 
	 * @param elementList
	 * 		List of wlan element 
	 */
	public static String getElementTaggedParameterSSID(IBeaconFrame beaconFrame)
	{
		if (beaconFrame == null) return "";
		StringBuffer sb = new StringBuffer();
		
		for (int j = 0; j < beaconFrame.getTaggedParameter().size(); j++) {
			IWlanElement elementList = beaconFrame.getTaggedParameter().get(j);
			if (elementList instanceof ISsidElement)
			{
				sb.append(((ISsidElement)elementList).getSsid()); 
			}
		}
		
		return sb.toString();
	}
}
