#!/system/bin/sh
#echo ""
#echo " This is for QCT monitor mode"
#echo ""

if [ "$1" == "STOP" ]; then
    echo 0 > /sys/module/wlan/parameters/con_mode
    ifconfig wlan0 up
    iwpriv wlan0 monitor 0
    echo "QCT SNIFFER MODE EXIT"
    return
fi

CHANNEL="$1"
BANDWIDTH="$2"
if [ "$CHANNEL" == "" ]; then
    CHANNEL=149
fi
if [ "$BANDWIDTH" == "" ]; then
    BANDWIDTH=40
fi
echo "sniffer.sh CHANNEL:$CHANNEL BANDWIDTH:$BANDWIDTH"

stop mpdecision
stop thermald
stop thermal-engine

echo 1 > /sys/devices/system/cpu/cpu0/online
echo 1 > /sys/devices/system/cpu/cpu1/online
echo 1 > /sys/devices/system/cpu/cpu2/online
echo 1 > /sys/devices/system/cpu/cpu3/online
sleep 1
#scaling_available_frequencies (C70, H443)
#200000 400000 533333 800000 998400 1094400 1152000 1209600
#300000 422400 652800 729600 883200 960000 1036800 1190400 1267200 1497600 1574400 1728000 1958400 2150400 (T1)
echo 2265600 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq
echo 2265600 > /sys/devices/system/cpu/cpu1/cpufreq/scaling_max_freq
echo 2265600 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_max_freq
echo 2265600 > /sys/devices/system/cpu/cpu3/cpufreq/scaling_max_freq

echo 2265600 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq
echo 2265600 > /sys/devices/system/cpu/cpu1/cpufreq/scaling_min_freq
echo 2265600 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_min_freq
echo 2265600 > /sys/devices/system/cpu/cpu3/cpufreq/scaling_min_freq




echo 4 > /sys/module/wlan/parameters/con_mode
ifconfig wlan0 up
iwpriv wlan0 MonitorModeConf $CHANNEL $BANDWIDTH 1 111 0
#iwpriv wlan0 MonitorFilter 00:11:22:34:57:31 1 0  0
iwpriv wlan0 monitor 1
echo "QCT SNIFFER MODE OK"


#setprop wlan.lge.sniffer.ipaddr 192.168.0.100
#setprop wlan.lge.sniffer.ssid .DIR815_5G