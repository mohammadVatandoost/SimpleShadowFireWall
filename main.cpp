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
#include <fstream>
#include<string.h> 

extern "C" {
    #include <pcap.h>
}

#include <httplib.h>
#include <json.hpp>


#define LogPacket false

using namespace std;

std::ofstream *outputFile;

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


void check_DOS_attack() {
   // check time interval of packets

   // if 3 packets come in DOS_Time_Theresould , push message to dosResult and print it
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

uint64_t startTime;

void check_dest_address() {
    // if it does not exist in valid routes, push message to unValidResults and print it
}

void saveMACAddresses(struct ethhdr *eth ) {
    char temp1[50],temp2[50];
    int n1 = std::sprintf (temp1, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    int n2 = std::sprintf (temp2, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    (*outputFile)<< std::string(temp1)<<",";
    (*outputFile)<< std::string(temp2)<<",";
}

void saveTime() {
    uint64_t microseconds_since_epoch = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    (*outputFile)<< microseconds_since_epoch<<",";
}

void process_packet( const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size= header->len;
	

	/*Ethernet*/
	struct ethhdr *eth = (struct ethhdr *)buffer;
    if(LogPacket) {
        printf("-------------------------------------\n");
	printf("Ethernet: \n");
	printf( "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	printf( "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
    }

    saveTime();
    saveMACAddresses(eth );
    (*outputFile)<< (unsigned short)eth->h_proto << ",";
	/*IP*/
	struct iphdr *iph=(struct iphdr *) (buffer + sizeof(struct ethhdr));
	int iphdrlen=iph->ihl*4;
	struct sockaddr_in source,dest;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
if(LogPacket) {
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
}

    (*outputFile)<< (unsigned int)iph->version<< ",";
    (*outputFile)<< (unsigned int)iph->ihl<< ",";
    (*outputFile)<< ((unsigned int)(iph->ihl))*4<< ",";
    (*outputFile)<< (unsigned int)iph->tos<< ",";
    (*outputFile)<< ntohs(iph->tot_len)<< ",";
    (*outputFile)<< (unsigned int)iph->ttl<< ",";
    (*outputFile)<< (unsigned int)iph->protocol<< ",";
    (*outputFile)<< ntohs(iph->check)<< ",";
    (*outputFile)<< inet_ntoa(source.sin_addr)<< ",";
    (*outputFile)<< inet_ntoa(dest.sin_addr)<< ",";
    (*outputFile)<< std::endl;

    int header_size=0;
	/*ICMP*/
	if(iph->protocol==1)
	{
	
		struct icmphdr *icmph = (struct icmphdr *)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	
		if(LogPacket) {
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
		
	
		
	}

	/*TCP*/
	if(iph->protocol==6)
	{


		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

		header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     if(LogPacket) { 
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

     }
	}

	/*UDP*/
	if(iph->protocol==17)
	{
	
		struct udphdr *udph = (struct udphdr*)(buffer + iphdrlen  + sizeof(struct ethhdr));
	
		header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
	 if(LogPacket) { 
	
		printf("\nUDP Header\n");
		printf("   |-Source Port      : %d\n" , ntohs(udph->source));
		printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
		printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
		printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));
		
		printf("\n");
     }
	}




}

void packetHandler(u_char *useprData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  process_packet(pkthdr,packet);
  if(LogPacket) { 
       cout << ++packetCount << " packet(s) captured" << endl;
  cout<<"Packet length:"<<pkthdr->len<<", time interval:" << pkthdr->ts.tv_sec <<endl;
//   cout<<"useprData:"<<useprData<<endl;
  cout<<"Packet:"<<string((char*)packet)<<endl;
  }
 
}


void routes() {
  httplib::Server svr;
  svr.Get("/dashboard", [](const httplib::Request &, httplib::Response &res) {
      res.set_header("Access-Control-Allow-Origin", "*");
	  mLock.lock();
      nlohmann::json response;
      nlohmann::json blackListJSONArray;
	  nlohmann::json blackListResJSONArray;
	  nlohmann::json DOSResJSONArray;
	  nlohmann::json unvalidRoutesJSONArray;
	  nlohmann::json unvalidRoutesResJSONArray;

      for(auto it = bItems.begin(); it != bItems.end(); it++) {
		  blackListJSONArray.push_back(it->second.ipAddr+":"+std::to_string(it->second.portNumber)) ;
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

svr.Post("/add-black-list", [&](const httplib::Request &req, httplib::Response &res)
			 {
				 nlohmann::json bojason;
				 stringstream ss;
				 string str;
				 try
				 {
					 using json = nlohmann::json;
					 res.set_header("Access-Control-Allow-Origin", "*");
					 json s = req.body;
					 bojason = nlohmann::json::parse(req.body);
					 auto ip = (std::__cxx11::string)bojason["ip"];
					 auto port = bojason["port"];
					 ss << port;
					 ss >> str;
					 std::cout << " add-black-list request, ip:" << ip << ", port:" << port << std::endl;
					 BlackItem bItem;
					 bItem.ipAddr = ip;
					 bItem.portNumber = port;
					 mLock.lock();
					 bItems.insert(std::pair<std::string, BlackItem>(ip + ":" + str, bItem));
					 mLock.unlock();
					 res.status = 200;
					 cout << "Inside try \n";
				 }
				 catch (const std::exception &e)
				 {
					 std::cout << "exception caught: " << e.what() << '\n';
				 }
			 });
  svr.listen("localhost", 9595);
}


int main() {
  char *dev;
  pcap_t *descr;
  startTime = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  char errbuf[PCAP_ERRBUF_SIZE];

  std::thread httpHandler (routes);
  int number_of_time_slots = 100; 
  

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
  for(int i=0; i< number_of_time_slots; i++) {
      cout<<"----- time slot :"<< i << "--------------" << endl;
       outputFile = new std::ofstream ("packetsData_"+std::to_string(i)+".csv");
   (*outputFile) << "Time(uS) , Destination Address , Source Address, Protocol, IP Version, IP Header Length , "<<
             " Type Of Service , IP Total Length , Identification, TTL, Protocol, Checksum, Source IP, Destination IP " <<  std::endl;
  if (pcap_loop(descr, 100, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }

   outputFile->close();

  }
 
  cout<<"listening to http reques" << endl;
  httpHandler.join();

  cout << "Shadow firewall finished" << endl;

  return 0;
}
