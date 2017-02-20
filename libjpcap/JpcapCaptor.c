#ifdef WIN32
#include<winsock2.h>
#include<iphlpapi.h>
#endif /* for WIN32 */

#include<jni.h>
#include<pcap.h>

//#include<net/bpf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#ifndef WIN32
#include<sys/param.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<errno.h>
#define __FAVOR_BSD
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#ifndef SIOCGIFCONF
#include<sys/sockio.h>
#endif
#ifndef SIOCGIFHWADDR
#include<ifaddrs.h>
#include<net/if_dl.h>
#endif
#endif

#include<netinet/in_systm.h>
#include<netinet/ip.h>

#include<string.h>
//#include<string>

#include"Jpcap_sub.h"
#include"Jpcap_ether.h"

#include <cutils/properties.h>

#ifdef INET6
#ifndef WIN32
#define COMPAT_RFC2292
#include<netinet/ip6.h>
//#include<netinet6/ah.h>
#else
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
typedef int            pid_t;
#define IPPROTO_HOPOPTS        0 /* IPv6 Hop-by-Hop options */
#define IPPROTO_IPV6          41 /* IPv6 header */
#define IPPROTO_ROUTING       43 /* IPv6 Routing header */
#define IPPROTO_FRAGMENT      44 /* IPv6 fragmentation header */
#define IPPROTO_ESP           50 /* encapsulating security payload */
#define IPPROTO_AH            51 /* authentication header */
#define IPPROTO_ICMPV6        58 /* ICMPv6 */
#define IPPROTO_NONE          59 /* IPv6 no next header */
#define IPPROTO_DSTOPTS       60 /* IPv6 Destination options */
#include<ws2tcpip.h>
//#include<tpipv6.h> //no longer needed for .Net VC
#include<netinet/ip6.h>
//#include<netinet6/ah.h>
#endif
#endif

#pragma export on
#include"jpcap_JpcapCaptor.h"
#pragma export reset

const int offset_type[]={0,12,-1,-1,-1,-1,20,-1,-1,2,
#ifdef PCAP_FDDIPAD
			  19+PCAP_FDDIPAD,
#else
			  19,
#endif
			  6,-1,-1,5};

const int offset_data[]={4,14,-1,-1,-1,-1,22,-1,16,4,
#ifdef PCAP_FDDIPAD
			   21+PCAP_FDDIPAD,
#else
			   21,
#endif
			   8,0,24,24};

const int pppoe_offset=8;

//#define DEBUG
//#define DEBUG_HEXDUMP

#define get_network_type(data,id,offset) ntohs(*(u_short *)(data+offset_type[linktypes[id]]+offset))

#define skip_datalink_header(data,id,offset)  (data+offset_data[linktypes[id]]+offset)

#define datalink_hlen(id,offset) (offset_data[linktypes[id]]+offset)
#define DATALINK_HLEN_DLT_LINUX_SLL 16
#define get_network_type_linux_sll(data) ntohs(*(u_short *)(data+DATALINK_HLEN_DLT_LINUX_SLL-2))
#define skip_datalink_header_linux_sll(data)  (data+DATALINK_HLEN_DLT_LINUX_SLL)

#define UNKNOWN_PROTO 0xffff

pcap_t *pcds[MAX_NUMBER_OF_INSTANCE];
JNIEnv *jni_envs[MAX_NUMBER_OF_INSTANCE];
char pcap_errbuf[PCAP_ERRBUF_SIZE][MAX_NUMBER_OF_INSTANCE];

jclass Jpcap=NULL,JpcapHandler,Interface,IAddress,Packet,DatalinkPacket,EthernetPacket,
	IPPacket,TCPPacket,UDPPacket,ICMPPacket,IPv6Option,ARPPacket,String,Thread,
	UnknownHostException,IOException,PPPOEPacket,W80211Packet;

jmethodID deviceConstMID,addressConstMID,handleMID,setPacketValueMID,setDatalinkPacketMID,
  setPacketHeaderMID,setPacketDataMID,
  setEthernetValueMID,setIPValueMID,setIPv4OptionMID,setIPv6ValueMID,addIPv6OptHdrMID,
  setTCPValueMID,setTCPOptionMID,setUDPValueMID,
  setICMPValueMID,setICMPIDMID,setICMPTimestampMID,setICMPRedirectIPMID,getICMPRedirectIPMID,
  setICMPRouterAdMID,setV6OptValueMID,setV6OptOptionMID,setV6OptFragmentMID,
  setV6OptRoutingMID,setV6OptAHMID,
  setARPValueMID,
  getSourceAddressMID,getDestinationAddressMID,
  setPPPOEValueMID,
  setW80211PacketMID;

int linktypes[MAX_NUMBER_OF_INSTANCE];
//Mark the protocal type between datalink layer and network layer
int linktypes_ext[MAX_NUMBER_OF_INSTANCE];

bpf_u_int32 netnums[MAX_NUMBER_OF_INSTANCE],netmasks[MAX_NUMBER_OF_INSTANCE];
jobject jpcap_handlers[MAX_NUMBER_OF_INSTANCE];
char pcap_errbuf[PCAP_ERRBUF_SIZE][MAX_NUMBER_OF_INSTANCE];

void set_info(JNIEnv *env,jobject obj,pcap_t *pcd);
void set_Java_env(JNIEnv *);
int get_packet(struct pcap_pkthdr,u_char *,jobject *,int);
void dispatcher_handler(u_char *,const struct pcap_pkthdr *,const u_char *);

struct ip_packet *getIP(char *payload);

u_short analyze_ip(JNIEnv *env,jobject packet,u_char *data);
u_short analyze_tcp(JNIEnv *env,jobject packet,u_char *data);
void analyze_udp(JNIEnv *env,jobject packet,u_char *data);
void analyze_icmp(JNIEnv *env,jobject packet,u_char *data,u_short len);
#ifdef INET6
u_short analyze_ipv6(JNIEnv *env,jobject packet,u_char *data);
#endif
int analyze_arp(JNIEnv *env,jobject packet,u_char *data);
jobject analyze_datalink(JNIEnv *env,struct pcap_pkthdr *header,u_char *data,int linktype,int linktype_ext);

//Added on 5.13 2012
jfieldID jpcapID;
jobject jpcapFilter, protocols, hosts, srcHosts, destHosts, ports, srcPorts, destPorts;
jclass JpcapFilter=NULL;
jmethodID compareProtocolMID, compareAddressMID, comparePortMID, getJpcapFilterMID, getHostsMID,
	getPortsMID, getProtocolsMID, getSrcHostsMID, getDestHostsMID, getSrcPortsMID, getDestPortsMID,
	isListEmptyMID;

void initJpcapFilter(JNIEnv *,jobject);
int get_next_packet(JNIEnv *, struct pcap_pkthdr *, jobject *, int);
int jpcap_host_filter(JNIEnv *, jbyteArray, jobject);
int jpcap_port_filter(JNIEnv *, jshort, jobject);
int jpcap_protocol_filter(JNIEnv *, char *);
int isEmpty(JNIEnv *, jobject);
int doFilter(JNIEnv *, jobject *);
int setDriverMonitorMode(int nOn);
int getWifiChipVendor();

#ifndef PROPERTY_VALUE_MAX
#define PROPERTY_VALUE_MAX  92
#endif

enum wifi_chip_vendor {
    WIFI_CHIP_BROADCOM = 1,
    WIFI_CHIP_QCT = 2,
    WIFI_CHIP_UNKNOWN = 98,
    WIFI_CHIP_NOT_DEFINE = 99
};
int WIFI_CHIP_VENDOR = WIFI_CHIP_NOT_DEFINE;

void display_hexdump(const char *title, const u_char *buf, size_t len)
{
	size_t i;
	const char *display;
	char *strbuf = NULL;
	size_t slen = len;
	if (buf == NULL) {
		display = " [NULL]";
	} else if (len == 0) {
		display = "";
	} else if (len) {
		/* Limit debug message length for log */
		if (slen > 255)
			slen = 255;
		strbuf = malloc(1 + 3 * slen);
		if (strbuf == NULL) {
			return;
		}

		for (i = 0; i < slen; i++)
			snprintf(&strbuf[i * 3], 4, " %02x",
				    buf[i]);

		display = strbuf;
	} else {
		display = " [REMOVED]";
	}

	LOGD("%s - hexdump(len=%lu):%s%s", title, (long unsigned int) len, display, len > slen ? " ..." : "");

	memset(strbuf, 0, 1 + 3 * slen);
	free(strbuf);
	return;
}

int getJpcapID(JNIEnv *env,jobject obj)
{
	return GetIntField(Jpcap,obj,"ID");
}

jbyteArray getAddressByteArray(JNIEnv *env,struct sockaddr *addr)
{
	jbyteArray array;
	if(addr==NULL) return NULL;

	switch(addr->sa_family){
		case AF_INET:
			array=(*env)->NewByteArray(env,4);
			(*env)->SetByteArrayRegion(env,array,0,4,(jbyte *)&((struct sockaddr_in *)addr)->sin_addr);
			break;
		case AF_INET6:
			array=(*env)->NewByteArray(env,16);
			(*env)->SetByteArrayRegion(env,array,0,16,(jbyte *)&((struct sockaddr_in6 *)addr)->sin6_addr);
			break;
		default:
			//LOGD("AF:%d\n",addr->sa_family);
			return NULL;
			break;
	}
	return array;
}

/**
Get Interface List
**/
JNIEXPORT jobjectArray JNICALL Java_jpcap_JpcapCaptor_getDeviceList
  (JNIEnv *env, jclass cl)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	pcap_addr_t *a;
	pcap_t *tmp_pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	int i=0,j=0,k=0;
	jobjectArray devices=NULL;
	jobjectArray addresses=NULL;
	jobject device=NULL;
	jobject address=NULL;
	int linktype;
	jstring lname,ldesc;
#ifdef WIN32
    u_long size=0;
	PIP_INTERFACE_INFO pInfo = NULL;
	MIB_IFROW MibIfRow;
	char **devnames;
	char *p1,*p2,*p3;
#else
#ifdef SIOCGIFHWADDR // Linux
    int sd;
    struct ifreq ifr;
	u_char buf[6];
#else //FreeBSD
    struct ifaddrs *ifa, *ifa0;
    struct sockaddr_dl* dl;

    getifaddrs(&ifa0);
#endif
#endif
	setDriverMonitorMode(1);

	Interface=FindClass("jpcap/NetworkInterface");
	//LOGD("Class jpcap.NetworkInterface = %x", Interface);
	deviceConstMID=(*env)->GetMethodID(env,Interface,"<init>","(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;[B[Ljpcap/NetworkInterfaceAddress;)V");

	IAddress=FindClass("jpcap/NetworkInterfaceAddress");

	addressConstMID=(*env)->GetMethodID(env,IAddress,"<init>","([B[B[B[B)V");
	//LOGD("NetworkInterfaceAddress constructor = %x", addressConstMID);

	(*env)->ExceptionDescribe(env);

	/* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
		LOGD("Error in pcap_findalldevs: %s", errbuf);
        //fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        return NULL;
    }

	//count # of devices
	for(i=0,d=alldevs;d;d=d->next,i++);

	LOGD("getDeviceList: Create devices num = %d", i);
	//create array
	devices=(*env)->NewObjectArray(env,(jsize)i,Interface,NULL);

#ifdef WIN32
	//obtain necessary size
	GetInterfaceInfo(NULL, &size);
	//allocate memory
	pInfo = (PIP_INTERFACE_INFO) malloc (size);
	if(GetInterfaceInfo(pInfo, &size)!=NO_ERROR){
		Throw(IOException,"GetInterfaceInfo failed.");
		return NULL;
	}
#endif

	/* Set Interface data */
    for(i=0,d=alldevs;d;d=d->next)
    {
		jbyteArray mac=(*env)->NewByteArray(env,6);
		//set mac
#ifdef WIN32
		// compare the device names obtained from Pcap and from IP Helper
		// in order to identify MAC address
		// since device name differs in 9x and NT/XP, compare name
		// from the end (not sure if this works in every case. I hope it does..)
		p1=d->name;
		while(*p1!=0) p1++;  //find the end

		//convert wchar to char
		devnames=(char **)malloc(sizeof(char *)*pInfo->NumAdapters);
		for(j=0;j<pInfo->NumAdapters;j++){
			size=WideCharToMultiByte(0,0,pInfo->Adapter[j].Name,-1,NULL,0,NULL,NULL);
			devnames[j]=(char *)malloc(size);
			WideCharToMultiByte(0,0,pInfo->Adapter[j].Name,-1,devnames[j],size,NULL,NULL);
			//LOGD("%s\n",devnames[j]);
		}

		for(j=0;j<pInfo->NumAdapters;j++){
			p2=p1;
			p3=devnames[j];
			while(*p3!=0) p3++; //find the end
			k=0;
			//LOGD("%s,%s:%d\n",d->name,devnames[j],j);
			while(*p2==*p3){
				p2--; p3--; k++;
				//LOGD("%c,%c,%d\n",*p2,*p3,k);
			}
			if(k<30) continue;

			//found! set MAC address
			MibIfRow.dwIndex=pInfo->Adapter[j].Index;
			GetIfEntry(&MibIfRow);
			(*env)->SetByteArrayRegion(env,mac,0,MibIfRow.dwPhysAddrLen,MibIfRow.bPhysAddr);
		}

#else
#ifdef SIOCGIFHWADDR  //Linux
    /* make socket */
    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sd < 0) {
		LOGD( "cannot open socket - return NULL ");
		Throw(IOException,"cannot open socket.");
        return NULL; // error: can't create socket.
    }

    /* set interface name (lo, eth0, eth1,..) */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_ifrn.ifrn_name,d->name, IFNAMSIZ);

    /* get a Get Interface Hardware Address */
    ioctl(sd, SIOCGIFHWADDR, &ifr);

    close(sd);

	(*env)->SetByteArrayRegion(env,mac,0,6,ifr.ifr_ifru.ifru_hwaddr.sa_data);
#else //FreeBSD
    for(ifa=ifa0;ifa;ifa=ifa->ifa_next){
        dl=(struct sockaddr_dl*)ifa->ifa_addr;
        if(dl->sdl_nlen>0 && strncmp(d->name,dl->sdl_data,dl->sdl_nlen)==0){
            (*env)->SetByteArrayRegion(env,mac,0,6,LLADDR(dl));
        }
    }
#endif
#endif

		//count # of addresses
		for(j=0,a=d->addresses;a;a=a->next)
			if(getAddressByteArray(env,a->addr)) j++;

		//create array of addresses
		addresses=(*env)->NewObjectArray(env,(jsize)j,IAddress,NULL);

		//set address data
		for(j=0,a=d->addresses;a;a=a->next)
		{
			jbyteArray addr=getAddressByteArray(env,a->addr);
			if(addr){
				address=(*env)->NewObject(env,IAddress,addressConstMID,
					addr,getAddressByteArray(env,a->netmask),
					getAddressByteArray(env,a->broadaddr),getAddressByteArray(env,a->dstaddr));
				(*env)->SetObjectArrayElement(env,addresses,j++,address);
			}
		}

		//get datalink name
		tmp_pcap=pcap_open_live(d->name,0,0,1000,errbuf);
		if(tmp_pcap!=NULL){
			linktype=pcap_datalink(tmp_pcap);
			lname=NewString(pcap_datalink_val_to_name(linktype));
			ldesc=NewString(pcap_datalink_val_to_description(linktype));
			pcap_close(tmp_pcap);
		}else{
			lname=NewString("Unknown");
			ldesc=NewString("Unknown");
		}

		device=(*env)->NewObject(env,Interface,deviceConstMID,NewString(d->name),
			NewString(d->description),(d->flags&PCAP_IF_LOOPBACK?JNI_TRUE:JNI_FALSE),lname,ldesc,mac,addresses);
		(*env)->SetObjectArrayElement(env,devices,i++,device);

		DeleteLocalRefEx(device);
		DeleteLocalRefEx(mac);
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

	(*env)->ExceptionDescribe(env);

#ifndef WIN32
#ifdef SIOCGIFHWADDR
#else
    freeifaddrs(ifa0);
#endif
#endif
    //LOGD( "return devices");
	return devices;
}

/**
Open Device for Live Capture
**/
JNIEXPORT jstring JNICALL
Java_jpcap_JpcapCaptor_nativeOpenLive(JNIEnv *env,jobject obj,jstring device,jint snaplen,
			  jint promisc,jint to_ms)
{
  char *dev;
  jint id;

  set_Java_env(env);

  id=getJpcapID(env,obj);

  if(pcds[id]!=NULL){
	return NewString("Another Jpcap instance is being used.");
  }

  jni_envs[id]=env;

  if(device==NULL){
    return NewString("Please specify device name.");
  }
  dev=(char *)GetStringChars(device);

  pcds[id]=pcap_open_live(dev,snaplen,promisc,to_ms,pcap_errbuf[id]);
  if(pcap_lookupnet(dev,&netnums[id],&netmasks[id],pcap_errbuf[id])==-1){
	netmasks[id] = 0;
  }

  ReleaseStringChars(device,dev);

  if(pcds[id]==NULL) return NewString(pcap_errbuf[id]);

  //set_info(env,obj,pcds[id]);
  //linktypes[id]=pcap_datalink(pcds[id]);
  if (getWifiChipVendor() == WIFI_CHIP_BROADCOM) {
	linktypes[id] = DLT_IEEE802_11;
  } else {
	linktypes[id] = DLT_IEEE802_11_RADIO;
  }
  LOGD( "Java_jpcap_JpcapCaptor_nativeOpenLive pcap_datalink - linktypes[%d] == %d, pcds[0] == %x", id, linktypes[id], pcds[id]);
  return NULL;
}

/**
Open Dumped File
**/
JNIEXPORT jstring JNICALL
Java_jpcap_JpcapCaptor_nativeOpenOffline(JNIEnv *env,jobject obj,jstring filename)
{
  char *file;
  jint id;
  LOGD( "call Java_jpcap_JpcapCaptor_nativeOpenOffline");
  set_Java_env(env);

  id=getJpcapID(env,obj);

  if(pcds[id]!=NULL){
  	LOGD( "Java_jpcap_JpcapCaptor_nativeOpenOffline - Another Jpcap instance is being used.");
	return NewString("Another Jpcap instance is being used.");
  }
  jni_envs[id]=env;

  file=(char *)GetStringChars(filename);
  LOGD( "call pcap_open_offline : %s", file );
  pcds[id]=pcap_open_offline(file,pcap_errbuf[id]);

  ReleaseStringChars(filename,file);

  if(pcds[id]==NULL) {
  	LOGD( "pcds[%d] is NULL : %s", id, pcap_errbuf[id]);
  	return NewString(pcap_errbuf[id]);
  }

  //set_info(env,obj,pcds[id]);
  if(strstr(file, ".j.pcap")) {
	linktypes[id] = DLT_IEEE802_11;
	LOGD( "Current file is for DLT_IEEE802_11...");
  } else {
	linktypes[id]=pcap_datalink(pcds[id]);
  }
  LOGD( "call pcap_datalink - linktypes[%d] == %d", id, linktypes[id]);
  set_Java_env(env);
  return NULL;
}

/**
Close Live Capture Device
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapCaptor_nativeClose(JNIEnv *env,jobject obj)
{
  int id=getJpcapID(env,obj);
  if(pcds[id]!=NULL) {
  	LOGD( "call Java_jpcap_JpcapCaptor_nativeClose pcds[%d] = %x is set to null", id, pcds[id]);
  	pcap_close(pcds[id]);
  }
  pcds[id]=NULL;
}


/**
Process Packets
**/
JNIEXPORT jint JNICALL
Java_jpcap_JpcapCaptor_processPacket(JNIEnv *env,jobject obj,
			       jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_dispatch(pcds[id],cnt,dispatcher_handler,(u_char *)&id); //2016.02.15, jaeshick: compile error -id -> &id

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}

/**
Loop Packets
**/
JNIEXPORT jint JNICALL
Java_jpcap_JpcapCaptor_loopPacket(JNIEnv *env,jobject obj,
			    jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);
  initJpcapFilter(env, obj);
#ifdef DEBUG
  LOGD("loopPacket:[start]jni_envs[%d]:%x, jpcap_handlers:%x", id, jni_envs[id], jpcap_handlers[id]);
#endif
  pkt_cnt=pcap_loop(pcds[id],cnt,dispatcher_handler,(u_char *)&id); //2016.02.15, jaeshick: compile error -id -> &id
#ifdef DEBUG
  LOGD("loopPacket:[end]jni_envs[%d]:%x, jpcap_handlers:%x", id, jni_envs[id], jpcap_handlers[id]);
#endif
  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}


/**
Get One Packet
**/
JNIEXPORT jobject JNICALL
Java_jpcap_JpcapCaptor_getPacket(JNIEnv *env,jobject obj)
{
  struct pcap_pkthdr *header;
  jobject packet;
  int id=getJpcapID(env,obj);
  u_char *data;
  int res;
  initJpcapFilter(env,obj);
  res=pcap_next_ex(pcds[id],&header,(const u_char **)&data);

  switch(res){
	  case 0: //timeout
		  return NULL;
	  case -1: //error
		  return NULL;
	  case -2:
		  return GetStaticObjectField(Packet,"Ljpcap/packet/Packet;","EOF");
  }

  jni_envs[id]=env;
  if(data==NULL) return NULL;
  res = get_packet(*header,data,&packet,id);
  if(!res){
	  return NULL;
  }
  return packet;
}

/*
 * Class:     jpcap_JpcapCaptor
 * Method:    dispatchPacket
 * Signature: (ILjpcap/PacketReceiver;)I
 */
/*JNIEXPORT jint JNICALL Java_jpcap_JpcapCaptor_dispatchPacket
(JNIEnv *env,jobject obj, jint cnt,jobject handler)
{
  jint pkt_cnt;
  jint id=getJpcapID(env,obj);

  jni_envs[id]=env;
  jpcap_handlers[id]=(*env)->NewGlobalRef(env,handler);

  pkt_cnt=pcap_dispatch(pcds[id],cnt,dispatcher_handler,(u_char *)id);

  (*env)->DeleteGlobalRef(env,jpcap_handlers[id]);
  return pkt_cnt;
}*/


/*
 * Class:     jpcap_JpcapCaptor
 * Method:    setNonBlockingMode
 * Signature: (Z)V
 */
JNIEXPORT void JNICALL Java_jpcap_JpcapCaptor_setNonBlockingMode
(JNIEnv *env, jobject obj, jboolean non_blocking){
	jint id=getJpcapID(env,obj);
	pcap_setnonblock(pcds[id],non_blocking,pcap_errbuf[id]);
}

/*
 * Class:     jpcap_JpcapCaptor
 * Method:    isNonBlockinMode
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_jpcap_JpcapCaptor_isNonBlockinMode
(JNIEnv *env, jobject obj){
	jint id=getJpcapID(env,obj);
	int nonblocking=pcap_getnonblock(pcds[id],pcap_errbuf[id]);
	return (nonblocking!=0?JNI_TRUE:JNI_FALSE);
}


/**
Set Filter
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapCaptor_setFilter(JNIEnv *env,jobject obj,jstring condition,
			   jboolean opt)
{
  char *cdt=(char *)GetStringChars(condition);
  struct bpf_program program;
  int id=getJpcapID(env,obj);
  char *err=NULL;

  if(pcap_compile(pcds[id],&program,cdt,(opt==JNI_TRUE?-1:0),netmasks[id])!=0){
    err = pcap_geterr(pcds[id]);
    if (err == NULL)
      err = "pcap_compile failed";
  } else if(pcap_setfilter(pcds[id],&program)!=0){
    err = pcap_geterr(pcds[id]);
    if (err == NULL)
      err = "pcap_setfilter failed";
  }

  ReleaseStringChars(condition,cdt);


  if (err != NULL) {
    char buf[2048];
#ifdef WIN32
	strcpy_s(buf, 2048,"Error occurred while compiling or setting filter: ");
    strncat_s(buf, 2048, err, _TRUNCATE);
#else
	strcpy(buf, "Error occurred while compiling or setting filter: ");
    strncat(buf, err, 2047-strlen(buf));
#endif
	buf[2047] = 0;
    Throw(IOException, buf);
  }
}

/**
Break loop
**/
JNIEXPORT void JNICALL Java_jpcap_JpcapCaptor_breakLoop
(JNIEnv *env, jobject obj)
{
  int id=getJpcapID(env,obj);

  pcap_breakloop(pcds[id]);
}


/**
Update Statistics
**/
JNIEXPORT void JNICALL
Java_jpcap_JpcapCaptor_updateStat(JNIEnv *env,jobject obj)
{
  struct pcap_stat stat;
  jfieldID fid;
  int id=getJpcapID(env,obj);

  pcap_stats(pcds[id],&stat);

  fid=(*env)->GetFieldID(env,Jpcap,"received_packets","I");
  (*env)->SetIntField(env,obj,fid,(jint)stat.ps_recv);
  fid=(*env)->GetFieldID(env,Jpcap,"dropped_packets","I");
  (*env)->SetIntField(env,obj,fid,(jint)stat.ps_drop);
}

/**
Get Error Message
**/
JNIEXPORT jstring JNICALL
Java_jpcap_JpcapCaptor_getErrorMessage(JNIEnv *env,jobject obj)
{
  int id=getJpcapID(env,obj);
  return NewString(pcap_errbuf[id]);
}

/**
Set Packet Read Timeout (UNIX only)
**/
JNIEXPORT jboolean JNICALL Java_jpcap_JpcapCaptor_setPacketReadTimeout
(JNIEnv *env, jobject obj, jint millis)
{
    jboolean success = JNI_FALSE;

#ifndef WIN32
    jint id = getJpcapID(env, obj);
    int fd = pcap_fileno(pcds[id]);
    int s;
    struct timeval tv;

    tv.tv_usec = (millis % 1000) * 1000;
    tv.tv_sec = millis / 1000;
    s = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    success = (s==0?JNI_TRUE:JNI_FALSE);
#endif

    return success;
}

/**
Get Packet Read Timeout (UNIX only)
**/
JNIEXPORT jint JNICALL Java_jpcap_JpcapCaptor_getPacketReadTimeout
(JNIEnv *env, jobject obj)
{
    jint rval = -1;

#ifndef WIN32
    jint id = getJpcapID(env, obj);
    int fd = pcap_fileno(pcds[id]);
    int s;
    struct timeval tv;
    socklen_t len = sizeof(struct timeval);

    s = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &len);

    if (s == 0 && len == sizeof(struct timeval))
    {
        rval = (tv.tv_usec / 1000) + (tv.tv_sec * 1000);
    }
#endif

    return rval;
}

void dispatcher_handler(u_char *id,const struct pcap_pkthdr *header,
			const u_char *data)
{
  jobject packet;
  int ID = atoi((const char*)id);	//2016.02.15, jaeshick: compile error -add atoi
  int result;

  JNIEnv *env=jni_envs[ID];

//LOGD( "enter:%d\n",ID);
  result = get_packet(*header,(u_char *)data,&packet,ID);
//LOGD( "got packet:%d\n",ID);
  if(result){
	  (*env)->CallVoidMethod(env,jpcap_handlers[ID],handleMID,packet);
	  DeleteLocalRefEx(packet);
  }

//LOGD( "leave:%d\n",ID);
  YIELD();
}

int get_packet(struct pcap_pkthdr header,u_char *data,jobject *packet,int id){

  u_short nproto,tproto;
  int pass = 1;
  short clen=header.caplen,hlen;
  u_char *orig_data=data;
  jbyteArray dataArray;
  int is80211Packet=0;
  int isdltlinuxsll=0;
  JNIEnv *env=jni_envs[id];
  short offset=0;
  jobject dlpacket;
#ifdef DEBUG
  LOGD( "get_packet : linktypes[id] = %d ", linktypes[id]);
#endif
  // Analyze network protocol
  // patch from Kenta
  switch(linktypes[id]){
  case DLT_RAW:
    // based on the hack for Raw IP
    nproto=ETHERTYPE_IP;
	clen-=datalink_hlen(id,offset);
    break;
  case DLT_IEEE802:
  case DLT_EN10MB:
	nproto=get_network_type(data,id,offset);
	if(nproto==ETHERTYPE_PPPOE){
		offset=pppoe_offset;
		linktypes_ext[id]=ETHERTYPE_PPPOE;
		//after set the pppoe offset, retest the nproto and clen
		nproto=get_network_type(data,id,offset);
		if(nproto==ETHERTYPE_IP_PACKET)
			nproto=ETHERTYPE_IP;
		clen-=datalink_hlen(id,offset);
	}else
	{
		clen-=datalink_hlen(id,offset);
	}
    break;
  case DLT_LINUX_SLL:
  	isdltlinuxsll = 1;
	nproto = get_network_type_linux_sll(data);
	clen -= DATALINK_HLEN_DLT_LINUX_SLL;
    break;
  case DLT_IEEE802_11_RADIO:
  case DLT_IEEE802_11:
  	//201602.15, jaeshick: for debug - display hex dump
#ifdef DEBUG_HEXDUMP
	display_hexdump("IEEE802_11_RADIO", data, (size_t)clen);
#endif
	is80211Packet=1;
	nproto=UNKNOWN_PROTO;
	tproto=UNKNOWN_PROTO;
	break;
  case DLT_PRISM_HEADER:
  	//201602.15, jaeshick: for debug - display hex dump
	//display_hexdump("DLT_PRISM_HEADER", data, (size_t)clen);
	is80211Packet=1;
	nproto=UNKNOWN_PROTO;
	tproto=UNKNOWN_PROTO;
	break;
  default:
    // get_network_type() macro does NOT work for non-ether packets
    // and can cause crash
    nproto=UNKNOWN_PROTO;
    break;
  }

#ifdef DEBUG
  //LOGD("detect:%d\n",nproto);
#endif
  if(clen>0){
    switch(nproto){
    case ETHERTYPE_IP:
		if (isdltlinuxsll == 1){
		  clen-=((struct ip *)skip_datalink_header_linux_sll(data))->ip_hl<<2;
	      if(clen>0 &&
			  !(ntohs(((struct ip *)skip_datalink_header_linux_sll(data))->ip_off)&IP_OFFMASK))
			  tproto=((struct ip *)skip_datalink_header_linux_sll(data))->ip_p;
	      else
			tproto=ETHERTYPE_IP;
		} else {
		  clen-=((struct ip *)skip_datalink_header(data,id,offset))->ip_hl<<2;
	      if(clen>0 &&
			  !(ntohs(((struct ip *)skip_datalink_header(data,id,offset))->ip_off)&IP_OFFMASK))
			  tproto=((struct ip *)skip_datalink_header(data,id,offset))->ip_p;
	      else
			tproto=ETHERTYPE_IP;
		}
      break;
#ifdef INET6
    case ETHERTYPE_IPV6:
      clen-=40;
      if(clen>0){
	  	u_char *dp;
	  	if (isdltlinuxsll == 1){
		  dp=skip_datalink_header_linux_sll(data);
  	    } else {
		  dp=skip_datalink_header(data,id,offset);
	  	}
	struct ip6_ext *ip6_ext;

	tproto=((struct ip6_hdr *)dp)->ip6_nxt;
	while((tproto==IPPROTO_HOPOPTS || tproto==IPPROTO_DSTOPTS ||
	       tproto==IPPROTO_ROUTING || tproto==IPPROTO_AH ||
	       tproto==IPPROTO_FRAGMENT) && clen>0){
	  switch(tproto){
	  case IPPROTO_HOPOPTS: /* Hop-by-Hop option  */
	  case IPPROTO_DSTOPTS: /* Destination option */
	  case IPPROTO_ROUTING: /* Routing option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=(ip6_ext->ip6e_len+1)<<3;
	    clen-=(ip6_ext->ip6e_len+1)<<3;
	    break;
	  case IPPROTO_AH: /* AH option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=(ip6_ext->ip6e_len+2)<<2;
	    clen-=(ip6_ext->ip6e_len+2)<<2;
	    break;
	  case IPPROTO_FRAGMENT: /* Fragment option */
	    ip6_ext=(struct ip6_ext *)dp;
	    tproto=ip6_ext->ip6e_nxt;
	    dp+=8;
	    clen-=8;
	    break;
	  }
	  if(tproto==IPPROTO_ESP || tproto==IPPROTO_NONE)
	    tproto=-1;
	}
      }
      break;
#endif
    case ETHERTYPE_ARP:
      /** XXX - assume that ARP is for Ethernet<->IPv4 **/
      clen-=28;
      if(clen>0) tproto=ETHERTYPE_ARP;
      break;
    case UNKNOWN_PROTO: //patch from Kenta
      tproto = UNKNOWN_PROTO;
      break;
    default:
		tproto=get_network_type(data,id,offset);
    }
  }

  /** Check for truncated packet */
  if((tproto==IPPROTO_TCP && clen<TCPHDRLEN) ||
     (tproto==IPPROTO_UDP && clen<UDPHDRLEN) ||
     (tproto==IPPROTO_ICMP && clen<ICMPHDRLEN) ||
     (tproto==IPPROTO_ICMPV6 && clen<ICMPHDRLEN)){
    tproto=-1;
  }

#ifdef DEBUG
  //LOGD("create:%d\n",tproto);
#endif
  /** Create packet object **/
  switch(tproto){
  case IPPROTO_TCP:
	  if(jpcap_protocol_filter(env, "TCP")){
		  *packet=AllocObject(TCPPacket);
	  }else
	  {
		  pass = 0;
	  }
	  break;
  case IPPROTO_UDP:
	  if(jpcap_protocol_filter(env, "UDP")){
		  *packet=AllocObject(UDPPacket);
	  }else
	  {
		  pass = 0;
	  }
	  break;
  case IPPROTO_ICMP:
	  if(jpcap_protocol_filter(env, "ICMP")){
		  *packet=AllocObject(ICMPPacket);
	  }else
	  {
		   pass = 0;
	  }
	  break;
  case IPPROTO_ICMPV6:
	  if(jpcap_protocol_filter(env, "ICMP")){
		  *packet=AllocObject(ICMPPacket);
	  }else
	  {
		   pass = 0;
	  }
	  break;
  default:
    switch(nproto){
    case ETHERTYPE_IP:
      *packet=AllocObject(IPPacket);break;
#ifdef INET6
    case ETHERTYPE_IPV6:
      *packet=AllocObject(IPPacket);
	  break;
#endif
    case ETHERTYPE_ARP:
	case ETHERTYPE_REVARP:
		if(jpcap_protocol_filter(env, "ARP")){
			*packet=AllocObject(ARPPacket);
		}else
		{
			pass = 0;
		}
		break;
    default:
		if (is80211Packet == 1) {
			*packet=AllocObject(Packet);
		} else {
      		*packet=AllocObject(Packet);
		}
		break;
    }
  }
  if(pass == 0){
	  goto get_next_packet;
  }
  (*env)->CallVoidMethod(env,*packet,setPacketValueMID,
			     (jlong)header.ts.tv_sec,(jlong)header.ts.tv_usec,
			     (jint)header.caplen,(jint)header.len);

  //LOGD( "datalink:%d\n", linktypes[id]);
  /** Analyze Datalink**/
  dlpacket = analyze_datalink(env, &header, data, linktypes[id], linktypes_ext[id]);
  (*env)->CallVoidMethod(env, *packet, setDatalinkPacketMID, dlpacket);
  DeleteLocalRefEx(dlpacket);
  if (is80211Packet == 1) {
	goto get_next_packet;
  }

#ifdef DEBUG
  //LOGD("network:%x\n",nproto);
#endif

  /** Analyze Network**/
  if(nproto != UNKNOWN_PROTO) {
  	if (isdltlinuxsll == 1){
	  data=skip_datalink_header_linux_sll(data);
  	} else {
	  data=skip_datalink_header(data,id,offset);
  	}
  }

  switch(nproto){
  case ETHERTYPE_IP:
    clen=ntohs(((struct ip *)data)->ip_len);
    hlen=analyze_ip(env,*packet,data);
    break;
#ifdef INET6
  case ETHERTYPE_IPV6:
    clen=ntohs(((struct ip6_hdr *)data)->ip6_plen);
	clen+=40;
    hlen=analyze_ipv6(env,*packet,data);break;
#endif
  case ETHERTYPE_ARP:
    clen=hlen=analyze_arp(env,*packet,data);break;
  case UNKNOWN_PROTO:
    clen=header.caplen;
    hlen=0;
    break;
  default:
  	if (isdltlinuxsll == 1){
	  clen=header.caplen-DATALINK_HLEN_DLT_LINUX_SLL;
  	} else {
	  clen=header.caplen-datalink_hlen(id,offset);
  	}
	hlen=0;
    break;
  }

  if (isdltlinuxsll == 1){
	  if(nproto != UNKNOWN_PROTO &&
	     tproto != UNKNOWN_PROTO &&
		 clen>header.caplen-DATALINK_HLEN_DLT_LINUX_SLL)
		 clen=header.caplen-DATALINK_HLEN_DLT_LINUX_SLL;
  } else {
	  if(nproto != UNKNOWN_PROTO &&
	     tproto != UNKNOWN_PROTO &&
		 clen>header.caplen-datalink_hlen(id,offset))
		 clen=header.caplen-datalink_hlen(id,offset);
  }

  data+=hlen;
  clen-=hlen;
  LOGD( "clen = %d, nproto = %d, tproto:%d, pass = %d, hlen = %d", clen, nproto, tproto, pass, hlen);

  //LOGD("transport:%d\n",tproto);
  /** Analyze Transport **/
  switch(tproto){
  case IPPROTO_TCP:
    hlen=analyze_tcp(env,*packet,data); break;
  case IPPROTO_UDP:
	hlen=UDPHDRLEN;
    analyze_udp(env,*packet,data); break;
  case IPPROTO_ICMP:
    // updated by Damien Daspit 5/14/01
    //hlen=clen;
    hlen=ICMPHDRLEN;
	analyze_icmp(env,*packet,data,clen);break;
  case IPPROTO_ICMPV6:
    hlen=ICMPHDRLEN;
	analyze_icmp(env,*packet,data,clen);break;
  default:
  {
    //jbyteArray dataArray=(*env)->NewByteArray(env,clen);
    //(*env)->SetByteArrayRegion(env,dataArray,0,clen,data);
    //(*env)->CallVoidMethod(env,*packet,setPacketDataMID,dataArray);
    //DeleteLocalRefEx(dataArray);
    hlen=0;
    LOGE( "clen = %d, nproto = [%d], tproto:%d, pass = %d, hlen = %d", clen, nproto, tproto, pass, hlen);
	break;
  }
  }
  if(hlen>clen) //if the header is cut off
	  hlen=clen; //cut off hlen
  clen-=hlen;
  data+=hlen;
  hlen=(u_short)(data-orig_data);
  //LOGD( "set data: clen=%d, hlen=%d,total=%d/%d",clen,hlen,header.len,header.caplen);

  dataArray=(*env)->NewByteArray(env,hlen);
  (*env)->SetByteArrayRegion(env,dataArray,0,hlen,orig_data);
  (*env)->CallVoidMethod(env,*packet,setPacketHeaderMID,dataArray);
  DeleteLocalRefEx(dataArray);

  if(clen>=0){
    dataArray=(*env)->NewByteArray(env,(jsize)clen);
    (*env)->SetByteArrayRegion(env,dataArray,0,(jsize)clen,data);
    (*env)->CallVoidMethod(env,*packet,setPacketDataMID,dataArray);
    DeleteLocalRefEx(dataArray);
  }

  //Add the filter here
  if(jpcapFilter!=NULL){
	 pass = doFilter(env,packet);
  }
  get_next_packet:
  if(!pass){
	  return get_next_packet(env, &header, packet, id);
  }

  return 1;
}

void set_Java_env(JNIEnv *env){
  if(Jpcap!=NULL) return;
  LOGD( "call set_Java_env - Jpcap is NULL");
  GlobalClassRef(Jpcap,"jpcap/JpcapCaptor");
  GlobalClassRef(JpcapHandler,"jpcap/PacketReceiver");
  GlobalClassRef(Packet,"jpcap/packet/Packet");
  GlobalClassRef(DatalinkPacket,"jpcap/packet/DatalinkPacket");
  GlobalClassRef(EthernetPacket,"jpcap/packet/EthernetPacket");
  GlobalClassRef(IPPacket,"jpcap/packet/IPPacket");
  GlobalClassRef(TCPPacket,"jpcap/packet/TCPPacket");
  GlobalClassRef(UDPPacket,"jpcap/packet/UDPPacket");
  GlobalClassRef(ICMPPacket,"jpcap/packet/ICMPPacket");
  GlobalClassRef(IPv6Option,"jpcap/packet/IPv6Option");
  GlobalClassRef(ARPPacket,"jpcap/packet/ARPPacket");
  GlobalClassRef(String,"java/lang/String");
  GlobalClassRef(Thread,"java/lang/Thread");
  GlobalClassRef(UnknownHostException,"java/net/UnknownHostException");
  GlobalClassRef(IOException,"java/io/IOException");
  GlobalClassRef(PPPOEPacket,"jpcap/packet/PPPOEPacket");
  GlobalClassRef(JpcapFilter,"jpcap/JpcapFilter");
  GlobalClassRef(W80211Packet,"jpcap/packet/W80211Packet");


  if((*env)->ExceptionCheck(env)==JNI_TRUE){
	  (*env)->ExceptionDescribe(env);
	  return;
  }

  handleMID=(*env)->GetMethodID(env,JpcapHandler,"receivePacket",
				"(Ljpcap/packet/Packet;)V");
  setPacketValueMID=(*env)->GetMethodID(env,Packet,"setPacketValue",
					"(JJII)V");
  setDatalinkPacketMID=(*env)->GetMethodID(env,Packet,"setDatalinkPacket",
					   "(Ljpcap/packet/DatalinkPacket;)V");
  setPacketHeaderMID=(*env)->GetMethodID(env,Packet,"setPacketHeader","([B)V");
  setPacketDataMID=(*env)->GetMethodID(env,Packet,"setPacketData",
				       "([B)V");
  setEthernetValueMID=(*env)->GetMethodID(env,EthernetPacket,"setValue",
					  "([B[BS)V");
  // enable to generate pppoe packet
  setPPPOEValueMID=(*env)->GetMethodID(env,PPPOEPacket,"setValue",
					  "(BBB[BS)V");

  setW80211PacketMID=(*env)->GetMethodID(env,W80211Packet,"set80211PacketData",
					  "([BI)V");

  // updated by Damien Daspit 5/7/01
  setIPValueMID=(*env)->GetMethodID(env,IPPacket,"setIPv4Value",
		 "(BBZZZBZZZSSSSS[B[B)V");
  setIPv4OptionMID=(*env)->GetMethodID(env,IPPacket,"setOption","([B)V");
  // *******************************
  setIPv6ValueMID=(*env)->GetMethodID(env,IPPacket,"setIPv6Value",
				      "(BBISBS[B[B)V");
  addIPv6OptHdrMID=(*env)->GetMethodID(env,IPPacket,"addOptionHeader",
				       "(Ljpcap/packet/IPv6Option;)V");
  // updated by Damien Daspit 5/7/01
  setTCPValueMID=(*env)->GetMethodID(env,TCPPacket,"setValue","(IIJJZZZZZZZZIS)V");
  // *******************************
  setTCPOptionMID=(*env)->GetMethodID(env,TCPPacket,"setOption","([B)V");
  setUDPValueMID=(*env)->GetMethodID(env,UDPPacket,"setValue","(III)V");
  setICMPValueMID=(*env)->GetMethodID(env,ICMPPacket,"setValue","(BBS)V"); //2016.02.15, jaeshick: BBSSS -> BBS - change the ICMPPacket class's constructor
  setICMPIDMID=(*env)->GetMethodID(env,ICMPPacket,"setID","(SS)V");
  setICMPTimestampMID=(*env)->GetMethodID(env,ICMPPacket,"setTimestampValue",
					  "(III)V");
  setICMPRedirectIPMID=(*env)->GetMethodID(env,ICMPPacket,"setRedirectIP",
				       "([B)V");
  getICMPRedirectIPMID=(*env)->GetMethodID(env,ICMPPacket,"getRedirectIP",
				       "()[B");
  setICMPRouterAdMID=(*env)->GetMethodID(env,ICMPPacket,"setRouterAdValue",
					 "(BBS[Ljava/lang/String;[I)V");
  setV6OptValueMID=(*env)->GetMethodID(env,IPv6Option,"setValue",
				       "(BBB)V");
  setV6OptOptionMID=(*env)->GetMethodID(env,IPv6Option,"setOptionData",
					"([B)V");
  setV6OptRoutingMID=(*env)->GetMethodID(env,IPv6Option,"setRoutingOption",
					  "(BB[[B)V");
  setV6OptFragmentMID=(*env)->GetMethodID(env,IPv6Option,"setFragmentOption",
					  "(SZI)V");
  setV6OptAHMID=(*env)->GetMethodID(env,IPv6Option,"setAHOption",
				    "(II)V");
  getSourceAddressMID=(*env)->GetMethodID(env,IPPacket,"getSourceAddress",
					  "()[B");
  getDestinationAddressMID=(*env)->GetMethodID(env,IPPacket,
					       "getDestinationAddress",
					       "()[B");
  setARPValueMID=(*env)->GetMethodID(env,ARPPacket,"setValue",
				     "(SSSSS[B[B[B[B)V");

  compareProtocolMID=(*env)->GetMethodID(env,JpcapFilter,"compareProtocol", "(Ljava/lang/String;)I");
  compareAddressMID=(*env)->GetMethodID(env,JpcapFilter,"compareAddress", "(Ljava/util/List;[B)I");
  comparePortMID=(*env)->GetMethodID(env,JpcapFilter,"comparePort", "(Ljava/util/List;I)I");
  getHostsMID=(*env)->GetMethodID(env,JpcapFilter,"getHosts", "()Ljava/util/List;");
  getPortsMID=(*env)->GetMethodID(env,JpcapFilter,"getPorts", "()Ljava/util/List;");
  getProtocolsMID=(*env)->GetMethodID(env,JpcapFilter,"getProtocols", "()Ljava/util/List;");
  getSrcHostsMID=(*env)->GetMethodID(env,JpcapFilter,"getSrcHosts", "()Ljava/util/List;");
  getDestHostsMID=(*env)->GetMethodID(env,JpcapFilter,"getDestHosts", "()Ljava/util/List;");
  getSrcPortsMID=(*env)->GetMethodID(env,JpcapFilter,"getSrcPorts", "()Ljava/util/List;");
  getDestPortsMID=(*env)->GetMethodID(env,JpcapFilter,"getDestPorts", "()Ljava/util/List;");
  getJpcapFilterMID=(*env)->GetMethodID(env,Jpcap,"getJpcapFilter", "()Ljpcap/JpcapFilter;");
  isListEmptyMID=(*env)->GetMethodID(env,JpcapFilter,"isEmpty","(Ljava/util/List;)I");

  jpcapID=(*env)->GetFieldID(env,Jpcap,"ID","I");

  if((*env)->ExceptionCheck(env)==JNI_TRUE){
	  (*env)->ExceptionDescribe(env);
	  return;
  }
}
//When have a packet to pass the filter, if the packet fails to pass the filter, get the next packet.
int get_next_packet(JNIEnv *env, struct pcap_pkthdr *header, jobject *packet, int id){
  u_char *data;
  int res;

  res=pcap_next_ex(pcds[id],&header,(const u_char **)&data);

  switch(res){
	  case 0: //timeout
		  return 0;
	  case -1: //error
		  return 0;
	  case -2:
		  *packet = GetStaticObjectField(Packet,"Ljpcap/packet/Packet;","EOF");
		  return 1;
  }

  if(data==NULL) return 0;
  res = get_packet(*header,data,packet,id);
  if(!res){
	  return 0;
  }
  return 1;
}

void initJpcapFilter(JNIEnv *env,jobject obj){

	if(jpcapFilter == NULL){
		jpcapFilter=(*env)->CallObjectMethod(env, obj, getJpcapFilterMID);
	}

	if(jpcapFilter != NULL){
		hosts = (*env)->CallObjectMethod(env,jpcapFilter,getHostsMID);
		srcHosts = (*env)->CallObjectMethod(env,jpcapFilter,getSrcHostsMID);
		destHosts = (*env)->CallObjectMethod(env,jpcapFilter,getDestHostsMID);
		ports = (*env)->CallObjectMethod(env,jpcapFilter,getPortsMID);
		srcPorts = (*env)->CallObjectMethod(env,jpcapFilter,getSrcPortsMID);
		destPorts = (*env)->CallObjectMethod(env,jpcapFilter,getDestPortsMID);
		//protocols = (*env)->CallObjectMethod(env,jpcapFilter,getProtocolsMID);
	}
}

 //Resolve hosts comparison
int jpcap_host_filter(JNIEnv *env, jbyteArray address, jobject hosts){
	return (*env)->CallIntMethod(env, jpcapFilter, compareAddressMID, hosts, address);
}
//Resolve port comparison
int jpcap_port_filter(JNIEnv *env, jshort port, jobject ports){
	return (*env)->CallIntMethod(env, jpcapFilter, comparePortMID, ports, port);
}


jstring chars_to_jstring(JNIEnv* env, char* pat)
{
	jclass strClass =FindClass("Ljava/lang/String;");
	jmethodID ctorID = (*env)->GetMethodID(env, strClass, "<init>", "([B)V");
	jbyteArray bytes = (*env)->NewByteArray(env, strlen(pat));
	(*env)->SetByteArrayRegion(env, bytes, 0, strlen(pat), (jbyte*)pat);
	//jstring encoding = (*env)->NewStringUTF(env, "utf-8");
	return (jstring)(*env)->NewObject(env, strClass, ctorID, bytes);
}
//Resolve protocol
int jpcap_protocol_filter(JNIEnv *env, char *protocol){
	if(jpcapFilter != NULL){
		jstring pro = chars_to_jstring(env, protocol);
		return (*env)->CallIntMethod(env, jpcapFilter,compareProtocolMID, pro);
	}
	return 1;
}

//Whether a list is empty
int isEmpty(JNIEnv *env, jobject list){
	return (*env)->CallIntMethod(env, jpcapFilter, isListEmptyMID, list);
}

int doFilter(JNIEnv *env, jobject *packet){
	jbyteArray pkg_src_ip = NULL;
	jbyteArray pkg_dest_ip = NULL;
	jint pkg_src_port = NULL;
	jint pkg_dest_port = NULL;
	int pass = 1;
	//if hosts are filled but packet is not IPPacket, then failed to pass the filter
	if (IsInstanceOf(*packet, IPPacket))
	{
		pkg_src_ip=(*env)->CallObjectMethod(env,*packet,getSourceAddressMID);
		pkg_dest_ip=(*env)->CallObjectMethod(env,*packet,getDestinationAddressMID);
		// if port is filled, but packet is not TCP Packet, then failed to pass the filter
		if (IsInstanceOf(*packet, TCPPacket))
		{
			pkg_src_port = (jint)GetIntField(TCPPacket,*packet,"src_port");
			pkg_dest_port = (jint)GetIntField(TCPPacket,*packet,"dst_port");
		}else{
			if(isEmpty(env,ports) || isEmpty(env,srcPorts) || isEmpty(env,destPorts)){
				pass = 0;
			}
		}
	}else{
		if(isEmpty(env,hosts) || isEmpty(env,srcHosts) || isEmpty(env,destHosts)){
			pass = 0;
		}
	}
	//if hosts contain the source IP or destination IP,then packet pass the filter, otherwise failed to pass.
	if(pass){
		if(isEmpty(env,hosts)){
			pass = jpcap_host_filter(env, pkg_src_ip, hosts);
			pass = (pass || jpcap_host_filter(env, pkg_dest_ip, hosts));
		}
	}
	//if source IP is contained in Source Hosts in Jpcap Filter, packet pass the filter, otherwise failed to pass.
	if(pass){
		if(isEmpty(env,srcHosts)){
			pass = jpcap_host_filter(env, pkg_src_ip, srcHosts);
		}
	}
	//if destination IP is contained in Destination Hosts in Jpcap Filter, packet pass the filter, otherwise failed to pass.
	if(pass){
		if(isEmpty(env,destHosts)){
			pass = jpcap_host_filter(env,pkg_dest_ip, destHosts);
		}
	}
	// if TCP packet port is contained in Ports of Jpcap Filter, packet will pass the filter, otherwise failed to pass.
	if(pass){
		if(isEmpty(env,ports)){
			pass = jpcap_port_filter(env,pkg_src_port,ports);
			pass = pass || jpcap_port_filter(env,pkg_dest_port,ports);
		}
	}
	// if TCP packet source port is contained in Source Ports of Jpcap Filter, packet will pass the filter, otherwise failed to pass.
	if(pass){
		if(isEmpty(env,srcPorts)){
			pass = jpcap_port_filter(env, pkg_src_port, srcPorts);
		}
	}
	// if TCP packet destination port is contained in Destination Port of Jpcap Filter, the packet will pass the filter, otherwise failed to pass.
	if(pass){
		if(isEmpty(env,destPorts)){
			pass = jpcap_port_filter(env, pkg_dest_port, destPorts);
		}
	}
	return pass;
}

void displayRcStatus(int rc) {
	if (rc == -1) {
		LOGE("setDriverMonitorMode : Could not be run");
	} else {
		LOGD("setDriverMonitorMode : result of running command is %d", WEXITSTATUS(rc));
	}
}

// TO DO: we should run binary by property_set("ctl.start", "mydaemon")
int setMonitorModeBroadcom(int nOn) {
	int rc = 0;

	LOGD("Call setMonitorModeBroadcom");
	// on
	if (nOn == 1) {
		rc = system("ifconfig wlan0 down");
		displayRcStatus(rc);

		rc = system("ifconfig wlan0 up");
		displayRcStatus(rc);

		rc = system("wl mpc 0");
		displayRcStatus(rc);

		rc = system("wl PM 0");
		displayRcStatus(rc);

		rc = system("wl scansuppress 1");
		displayRcStatus(rc);

		rc = system("wl monitor 1");
		displayRcStatus(rc);
	} else {
		rc = system ("ifconfig wlan0 down");
		displayRcStatus(rc);
	}

	return rc;
}

int setMonitorModeQcom(int nOn) {
	int rc = 0;
	LOGD("Call setMonitorModeQcom");
	// on
/*
	if (nOn == 1) {
		rc = system("chmod 777 /data/misc/wifi/sniffer.sh");
		displayRcStatus(rc);

		rc = system("/data/misc/wifi/sniffer.sh 11 20");
		displayRcStatus(rc);

	} else {
		rc = system("chmod 777 /data/misc/wifi/sniffer.sh");
		displayRcStatus(rc);

		rc = system("/data/misc/wifi/sniffer.sh STOP");
		displayRcStatus(rc);
	}
*/
/*
	if (nOn == 1) {
		rc = system("echo 4 > /sys/module/wlan/parameters/con_mode");
		displayRcStatus(rc);
		sleep(2);

		rc = system("ifconfig wlan0 up");
		displayRcStatus(rc);

		sleep(1);
		rc = system("iwpriv wlan0 MonitorModeConf 1 20 1 111 0"); //iwpriv wlan0 MonitorModeConf $CHANNEL $BANDWIDTH 1 111 0
		displayRcStatus(rc);

		sleep(1);
		rc = system("iwpriv wlan0 monitor 1");
		displayRcStatus(rc);

	} else {
		rc = system("echo 0 > /sys/module/wlan/parameters/con_mode");
		displayRcStatus(rc);
		sleep(2);

		rc = system("ifconfig wlan0 up");
		displayRcStatus(rc);

		rc = system("iwpriv wlan0 monitor 0");
		displayRcStatus(rc);
	}
*/
	return rc;
}

int setDriverMonitorMode(int nOn) {

    switch (getWifiChipVendor()) {
    case WIFI_CHIP_BROADCOM:
        return setMonitorModeBroadcom(nOn);
    case WIFI_CHIP_QCT:
        return setMonitorModeQcom(nOn);
    default:
        return -1;
    }
}

int getWifiChipVendor() {
	if (WIFI_CHIP_VENDOR == WIFI_CHIP_NOT_DEFINE) {
		char propertyValVendor[PROPERTY_VALUE_MAX];
		int propertyLen = property_get("wlan.chip.vendor", propertyValVendor, "unknown");

		LOGD("getWifiChipVendor[wlan.chip.vendor] %s", propertyValVendor);
		if( propertyLen > 0 && !memcmp(propertyValVendor, "brcm", 4)){
			WIFI_CHIP_VENDOR = WIFI_CHIP_BROADCOM;
		} else if( propertyLen > 0 && !memcmp(propertyValVendor, "qcom", 4)){
			WIFI_CHIP_VENDOR = WIFI_CHIP_QCT;
		} else {
			WIFI_CHIP_VENDOR = WIFI_CHIP_UNKNOWN;
		}
	}

	return WIFI_CHIP_VENDOR;
}
