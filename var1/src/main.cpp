//#define HAVE_REMOTE

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <time.h>
#include <Winsock2.h>
#include <winsock.h>
#include <tchar.h>

/*#ifndef _WIN32
    #include <sys/socket.h>
    #include <netinet/in.h>
#else
    #include <winsock.h>
    #include <tchar.h>

*/

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
//#endif

//example, with only capturing devcie and packets

//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int inum;
    int i=0;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    //
    int res;
    struct tm *ltime;
    char timestr[16];
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    time_t local_tv_sec;

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

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);

    scanf_s("%d", &inum);

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
    if ( (adhandle= pcap_open(d->name,			// name of the device
                  65536,			// portion of the packet to capture
                                // 65536 guarantees that the whole packet will be captured on all the link layers
                  PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
                  1000,				// read timeout
                  NULL,				// authentication on the remote machine
                  errbuf			// error buffer
                  ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
        // Free the device list
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    //clearing device list
    pcap_freealldevs(alldevs);


    //filter


    //capture
    //pcap_loop(adhandle, 0, packet_handler, NULL);

    while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0){

        if(res == 0)
            // Timeout elapsed
            continue;

        // convert the timestamp to readable format
        local_tv_sec = header->ts.tv_sec;
        ltime=localtime(&local_tv_sec);
        strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
    }

    if(res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
        return -1;
    }


    return 0;
}


//func that will call, when get packet
/*void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;


    (VOID)(param);
    (VOID)(pkt_data);

    //convert the timestamp to readable format
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", &ltime);

    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

}*/




