package utils;

import java.util.List;

import android.util.Log;
import jpcap.JpcapCaptor;
import packetProcessor.NetworkSession;
import pcapmonitor.JpcapTools;

public class StatisticPrinter {

	public static void printStatistics(JpcapCaptor captor,
			List<NetworkSession> networkSessions, int numberOfCapturedPackets,
			int numberOfModifiedPackets) {
		StringBuilder statistics = new StringBuilder("Statistics:\n");
		int numberOfCapturedSessions = networkSessions.size();
		statistics.append("Sessions: " + numberOfCapturedSessions + "\n");
		NetworkSession currentSession = null;
		for (int sessionIndex = 0; sessionIndex < numberOfCapturedSessions; sessionIndex++) {
			currentSession = networkSessions.get(sessionIndex);
			statistics.append("Session " + sessionIndex + "\n" + currentSession
					+ "\n");
		}
		statistics.append("========Summary==========\ncaputed: "
				+ numberOfCapturedPackets + " received: "
				+ captor.received_packets + " dropped:"
				+ captor.dropped_packets + " modified: "
				+ numberOfModifiedPackets + "\n=========================\n");
		Log.d(JpcapTools.TAG, statistics.toString());
	}
}
