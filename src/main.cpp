#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <winsock.h>
#include <tchar.h>

BOOL LoadNpcapDlls()
{
    TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    return TRUE;
}


// ip
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// IPv4 header
typedef struct ip_header{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// type of service
    u_short tlen;			// total length
    u_short identification; // identification
    u_short flags_fo;		// flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// time to live
    u_char	proto;			// type of protocol
    u_short crc;			// checksum header
    ip_address	saddr;		// source address
    ip_address	daddr;		// sestination address
    u_int	op_pad;			// Option + Padding
}ip_header;

// header
typedef struct _header_{
    u_short sport;			// source port
    u_short dport;			// destination port
    u_short len;			// datagram length
    u_short crc;			// checksum
}udp_header;

// prototype of the packet handler
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    int res;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;



    bool loop=true;
    int choise;

    //select protocol
    while(loop){
        printf("Enter traffic type:1-tcp, 2-udp\n");
        scanf("%d", &choise);
        if(choise==1 || choise==2){
            loop=false;
        }else{
            choise=0;
        }

    }

    char packet_filter[200];

    *packet_filter='\0';

    if(choise==1){
        strcat(packet_filter,"ip and tcp");

    }else{
        strcat(packet_filter,"ip and udp");

    }

    char buff[20];
    loop=true;
    //enter src port
    loop=true;
    while(loop){
        printf("enter src port \n");
        scanf("%s",&buff);
        if(strlen(buff)<6 && atoi(buff)>0){
            loop=false;
        }else{
            printf("wrong port \n");
        }

    }


    strcat(packet_filter," src port ");

    strcat(packet_filter,buff);

    strcat(packet_filter," ");

    memset(buff,0,sizeof buff);

    //enter dst port
    loop=true;
    while(loop){
        printf("enter dst port \n");
        scanf("%s",&buff);
        if(strlen(buff)<6 && atoi(buff)>0){
            loop=false;
        }else{
            printf("wrong long port \n");
        }

    }

    strcat(packet_filter,"and dst port ");

    strcat(packet_filter,buff);

    strcat(packet_filter," ");

    memset(buff,0,sizeof buff);

    //enter src ip    
    loop=true;
    while(loop){
        printf("enter src ip \n");
        scanf("%s",&buff);
        if(strlen(buff)<16){
            loop=false;
        }else{
            printf("wrong ip \n");
        }

    }

    strcat(packet_filter,"and src net ");

    strcat(packet_filter,buff);

    strcat(packet_filter," ");

    memset(buff,0,sizeof buff);

    //enter src ip
    loop=true;
    while(loop){
        printf("enter dst ip \n");
        scanf("%s",&buff);
        if(strlen(buff)<16){
            loop=false;
        }else{
            printf("wrong ip \n");
        }

    }

    strcat(packet_filter,"and dst net ");

    strcat(packet_filter,buff);

    strcat(packet_filter," ");

    memset(buff,0,sizeof buff);

    printf("you choose(%d): %.100s \n",
           (int)sizeof(packet_filter),
           packet_filter);


    struct bpf_program fcode;

    //check is npcap loaded
    if (!LoadNpcapDlls())
    {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

    //getting list of devices
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    //show list of devices
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    //check is interfaces found
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);

    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        // Free the device list
        pcap_freealldevs(alldevs);
        return -1;
    }

    //select device
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    //Open the device
    if ( (adhandle= pcap_open(d->name,			// device name
                  65536,			// how much of packet we get
                                // 65536 guarantees that the whole packet will be captured on all the link layers
                  PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                  1000,				// read timeout
                  NULL,				// authentication on the remote machine
                  errbuf			// error buffer
                  ) ) == NULL)
    {
        fprintf(stderr,"\n Can't open the adapter. %s is not supported by Npcap\n", d->name);
        // Free the device list
        pcap_freealldevs(alldevs);
        return -1;
    }


    if(d->addresses != NULL)
        // Retrieve the mask of the first address of the interface
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        // If the interface is no addresses, be in a C class network
        netmask=0xffffff;

    //create filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        //clear
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set filter
    if (pcap_setfilter(adhandle, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        //
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    //clearing device list
    pcap_freealldevs(alldevs);

    //capture
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

//func that will call, when get packet
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    char timestr[16];
    ip_header *ih;
    _header_ *uh;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;



    //convert the timestamp to readable format
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);


    // retireve the position of the ip header
        ih = (ip_header *) (pkt_data +
            14); //length of ethernet header

    // retireve the position of the udp header
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header *) ((u_char*)ih + ip_len);

    sport=_byteswap_ushort(uh->sport);
    dport=_byteswap_ushort(uh->dport);


    //print protocol (17 - udp, 06 - tcp)
    if(ih->proto==17){
        printf("UDP ");
    }else if(ih->proto==6){
        printf("TCP ");
    }else{
        printf("%d",ih->proto);
    }

    //print packet source
    printf("from %d.%d.%d.%d:%d ",
           ih->saddr.byte1,
           ih->saddr.byte2,
           ih->saddr.byte3,
           ih->saddr.byte4,
           sport
           );

    //print packet destination
    printf("to %d.%d.%d.%d:%d ",
           ih->daddr.byte1,
           ih->daddr.byte2,
           ih->daddr.byte3,
           ih->daddr.byte4,
           dport
           );

    //lenght of packet
    printf("data lenght: %d \n", uh->len);
}




