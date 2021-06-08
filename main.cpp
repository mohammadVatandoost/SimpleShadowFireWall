#include <iostream>
#include <map>
#include <vector>
#include <thread>   
#include <mutex>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	
#include<netinet/udp.h>	
#include<netinet/tcp.h>	
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h> 
#include<string.h> 
#include<time.h>
#include<queue>
#include<map>
#include"md5.h"
extern "C" {
    #include <pcap.h>
}

#include <httplib.h>
#include <json.hpp>

using namespace std;

#define DOS_Time_Theresould 200  // mili second

static std::mutex mLock;

static int packetCount = 0;

struct BlackItem {
	int portNumber = 0;
	std::string ipAddr = "";
};

// first ip+port
std::map<string, BlackItem> bItems;
std::vector<string> blackAnalyseResult;

void check_black_list() {
    // check exist in bItem

	// if it was in black items, push message to blackAnalyseResult and print it
}


struct packetSource {
	int portNumber = 0;
	std::string ipAddr = "";
	double packet1Time = 0;
	double packet2Time = 0;
};
// first ip+port
std::map<string,packetSource> pSources;
std::vector<string> dosResult;

#define DOS_WINDOW 10 //secods
#define SRC_THRESH 10
#define SRC_DST_THRESH 5
struct dos_packet{
	long long time;
	std::string srcip;
	std::string dstip;
	std::string dstport;
};
std::map<std::string,int> src_count;
std::map<std::string,int> src_dst_count;
std::queue<dos_packet> dos_packet_queue;
std::hash<std::string> hash_func;
void check_DOS_attack(const char * src_ip, const char * dst_ip, int dst_port) {
    dos_packet p;
    p.time=(long long)time(NULL);
    p.srcip=std::string(src_ip);
    p.dstip=std::string(dst_ip);
    p.dstport=std::to_string(dst_port);
    dos_packet_queue.push(p);
    string src_hash="";
    string src_dst_hash="";
    while(dos_packet_queue.front().time<(p.time-DOS_WINDOW))
    {
	    dos_packet packet=dos_packet_queue.front();
	    //src_hash=hash_func(packet.srcip);
	    //src_dst_hash=hash_func(packet.srcip+packet.dstip+packet.dstport);
	    src_hash=md5(packet.srcip);
	    src_dst_hash=md5(packet.srcip+packet.dstip+packet.dstport);
	    src_count[src_hash]--;
	    src_dst_count[src_dst_hash]--;
	    dos_packet_queue.pop();
    }
    //src_hash=hash_func(p.srcip);
    //src_dst_hash=hash_func(p.srcip+p.dstip+p.dstport);
    src_hash=md5(p.srcip);
    src_dst_hash=md5(p.srcip+p.dstip+p.dstport);

    if(src_count.find(src_hash)==src_count.end())
	    src_count[src_hash]=0;
    if(src_dst_count.find(src_dst_hash)==src_dst_count.end())
	    src_dst_count[src_dst_hash]=0;
    
    src_count[src_hash]++;
    src_dst_count[src_dst_hash]++;
   
  //  cout<<"src_hash= "<<src_hash<<", src_count["<<src_hash<<"]="<<src_count[src_hash]<<"------ src_dst_hash="<<src_dst_hash<<",src_dst_count["<<src_dst_hash<<"]="<<src_dst_count[src_dst_hash]<<std::endl;

    string msg="Dos Attack: too many requests from ";


	  mLock.lock();
    if(src_count[src_hash]>SRC_THRESH)
    { 
	    dosResult.push_back(msg+p.srcip);
    	    src_count[src_hash]=0;
    }
    if(src_dst_count[src_dst_hash]>SRC_DST_THRESH)
    {
	    dosResult.push_back(msg+p.srcip+" to "+p.dstip+":"+p.dstport);
    	    src_dst_count[src_dst_hash]=0;
    }
  	    mLock.unlock();

}


struct packetInfo {
	int sourcePortNumber = 0;
	std::string sourceIpAddr = "";

    int destPortNumber = 0;
	std::string destIpAddr = "";
};

// source: ip+port,  dest: ip+port, 
std::map<string, string> validRoutes;
std::vector<string> unvalidRoutesResult;



void check_dest_address() {
    // if it does not exist in valid routes, push message to unValidResults and print it
}



void process_packet( const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size= header->len;
	printf("-------------------------------------\n");

	/*Ethernet*/
	struct ethhdr *eth = (struct ethhdr *)buffer;
	printf("Ethernet: \n");
	printf( "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	printf( "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
	
	
	/*IP*/
	struct iphdr *iph=(struct iphdr *) (buffer + sizeof(struct ethhdr));
	int iphdrlen=iph->ihl*4;
	struct sockaddr_in source,dest;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	printf("   |-Identification    : %d\n",ntohs(iph->id));
	printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
	printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
	printf("   |-Checksum : %d\n",ntohs(iph->check));
	printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
	printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
	
	int header_size=0;

	int port=0;
	
	/*ICMP*/
	if(iph->protocol==1)
	{
	
		struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	
			
		printf("\n");	
		printf("ICMP Header\n");
		printf("   |-Type : %d",(unsigned int)(icmph->type));
			
		if((unsigned int)(icmph->type) == 11)
		{
			printf("  (TTL Expired)\n");
		}
		else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
		{
			printf("  (ICMP Echo Reply)\n");
		}
	
		printf("   |-Code : %d\n",(unsigned int)(icmph->code));
		printf("   |-Checksum : %d\n",ntohs(icmph->checksum));
		printf("\n");
	
		
	}

	/*TCP*/
	if(iph->protocol==6)
	{


		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

		header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

		printf("\n");
		printf("TCP Header\n");
		printf("   |-Source Port      : %u\n",ntohs(tcph->source));
		printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
		printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
		printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
		printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
		printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
		printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
		printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
		printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
		printf("   |-Window         : %d\n",ntohs(tcph->window));
		printf("   |-Checksum       : %d\n",ntohs(tcph->check));
		printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
		printf("\n");
		printf("                        DATA Dump                         ");
		printf("\n");
		port=tcph->dest;
	
	}

	/*UDP*/
	if(iph->protocol==17)
	{
	
		struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	
	
		printf("\nUDP Header\n");
		printf("   |-Source Port      : %d\n" , ntohs(udph->source));
		printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
		printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
		printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
		
		printf("\n");
		port=udph->dest;
	}

	check_DOS_attack(inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr) ,port);


}

void packetHandler(u_char *useprData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  process_packet(pkthdr,packet);
  cout << ++packetCount << " packet(s) captured" << endl;
  cout<<"Packet length:"<<pkthdr->len<<", time interval:" << pkthdr->ts.tv_sec <<endl;
//   cout<<"useprData:"<<useprData<<endl;
  //cout<<"Packet:"<<string((char*)packet)<<endl;
}


void routes() {
  httplib::Server svr;
  svr.Get("/dashboard", [](const httplib::Request &, httplib::Response &res) {
	  mLock.lock();
      nlohmann::json response;
      nlohmann::json blackListJSONArray;
	  nlohmann::json blackListResJSONArray;
	  nlohmann::json DOSResJSONArray;
	  nlohmann::json unvalidRoutesJSONArray;
	  nlohmann::json unvalidRoutesResJSONArray;

      for(auto it = bItems.begin(); it != bItems.end(); it++) {
		  blackListJSONArray.push_back(it->second.ipAddr+std::to_string(it->second.portNumber)) ;
	  }

      for(auto v : blackAnalyseResult) {
          blackListResJSONArray.push_back(v);
      }

      for(auto v : dosResult) {
          DOSResJSONArray.push_back(v);
      }

      for(auto it = validRoutes.begin(); it != validRoutes.end(); it++) {
          blackListJSONArray.push_back(it->second) ;
      }

      for(auto v : unvalidRoutesResult) {
          unvalidRoutesResJSONArray.push_back(v);
      }

      response["blackList"] = blackListJSONArray;
      if(blackListJSONArray.empty() ) {response["blackList"] = "";}

      response["blackListResult"] = blackListResJSONArray;
      if(blackListResJSONArray.empty() ) {response["blackListResult"] = "";}

      response["DOSResult"] = DOSResJSONArray;
      if(DOSResJSONArray.empty() ) {response["DOSResult"] = "";}

      response["unvalidRoutes"] = blackListJSONArray;
      if(blackListJSONArray.empty()) {response["unvalidRoutes"] = "";}

      response["unvalidRoutesResult"] = unvalidRoutesResJSONArray;
      if(unvalidRoutesResJSONArray.empty()) {response["unvalidRoutesResult"] = "";}

      std::string responseString = response.dump();
      mLock.unlock();
      res.set_content(responseString, "text/plain");
  });
  svr.listen("localhost", 9595);
}

int main() {
  char *dev;
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  std::thread httpHandler (routes);
  
  

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
      cout << "pcap_lookupdev() failed: " << errbuf << endl;
      return 1;
  }

  descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  if (pcap_loop(descr, 20, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }


  httpHandler.join();
  cout << "Shadow firewall finished" << endl;

  return 0;
}
