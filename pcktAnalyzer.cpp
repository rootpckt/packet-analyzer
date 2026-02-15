#include <iostream>    // Provides input/output stream objects like std::cout for printing to console
#include <ctime>       // Contains definitions for time-related functions and types (e.g., time_t, tm, localtime)
#include <sys/time.h>  // Defines timeval struct and gettimeofday() for high-resolution time retrieval
#include <pcap.h>      // Declares libpcap functions/types for packet capture (e.g., pcap_lookupdev)
#include <netinet/ip.h> // this struct represents to IPv4 Header
#include <netinet/if_ether.h> // for Ethernet header definitions
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <iomanip>
#include <string>

using namespace std;   // Allows direct use of standard library names (cout, endl) without std:: prefix

int main() {           // Entry point of the program; returns int status code to OS upon exit

    //TIMESTAMP
    timeval ts;        // timeval is a struct representing time as seconds and microseconds since epoch
    gettimeofday(&ts, nullptr); // Fills ts with current time; nullptr means no timezone info requested

    time_t seconds = ts.tv_sec; // time_t holds time as seconds since Unix epoch (Jan 1, 1970)
    tm* timeinfo = localtime(&seconds);
    // localtime converts time_t to broken-down local time (year, month, day, etc.)
    // Returns pointer to statically allocated tm struct; pointer used to avoid copying large struct

    cout << "Time: "
         << timeinfo->tm_hour << ":"   // tm_hour is hours after midnight (0-23)
         << timeinfo->tm_min << ":"    // tm_min is minutes after the hour (0-59)
         << timeinfo->tm_sec << endl;  // tm_sec is seconds after the minute (0-60, leap seconds possible)
    // cout sends formatted output to standard output (console) at runtime

    /*
        // // raw_time stores the current time as seconds since the Unix epoch (January 1, 1970)
        // time_t raw_time;
        // // Fetch the current time and store it in raw_time
        // time(&raw_time);
        //
        // // Decode raw_time into a tm structure representing local time components
        // tm *timeinfo =z localtime(&raw_time);
        // // Format the tm structure as a human-readable string.
        // // Note: asctime uses a static buffer which may be overwritten by subsequent calls.
        // cout << asctime(timeinfo) << endl;
        */

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "pcap_findalldevs failed: " << errbuf << endl;
        return 1;
    }

    if (alldevs == nullptr) {
        cerr << "No devices found" << endl;
        return 1;
    }

    cout << "Device: " << alldevs->name << endl;

    pcap_freealldevs(alldevs);

    const char* device = "ap1";

    pcap_t* handle = pcap_open_live(
    "en0",
    65535,
    1,
    1000,
    errbuf
    );

    if ( !handle ) {
        cerr << "pcap_open_live failed: " << errbuf << endl;
        return 1;
    }

    pcap_pkthdr* header;
    const u_char* packet;

    int printed = 0;
    const int MAX_PACKETS = 10;

    cout << left << setw(5) << "No"
         <<setw(10) << "Timestamp"
         << setw(16) << "Source"
         << setw(16) << "Destination"
         << setw(8) << "Proto"
         << setw(6) << "Len" << endl;

    while (printed < MAX_PACKETS) {
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 1) {
            // Parse Ethernet header

            time_t packet_sec = header->ts.tv_sec;
            tm* packet_time = localtime(&packet_sec);
            char timebuf[9];
            strftime(timebuf, sizeof(timebuf), "%H:%M:%S", packet_time);
            struct ether_header* eth = (struct ether_header*)packet;
            if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
                // cout << "Non-IPv4 packet" << endl;
                continue;
            }
            // Parse IPv4 header
            struct ip* iphdr = (struct ip*)(packet + sizeof(struct ether_header));
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &iphdr->ip_src, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &iphdr->ip_dst, dst_ip, INET_ADDRSTRLEN);

            string proto;
            if ( iphdr->ip_p == IPPROTO_TCP ) {
                proto = " TCP";
            } else if ( iphdr->ip_p == IPPROTO_UDP ) {
                proto = " UDP";
            } else if ( iphdr->ip_p == IPPROTO_ICMP ) {
                proto = " ICMP";
            } else {
                proto = " OTHER";
            }

            cout << left << setw(5) << printed + 1
                 <<setw(10) << timebuf
                 << setw(16) << src_ip
                 << setw(16) << dst_ip
                 << setw(8) << proto
                 << setw(6) << header->len << endl;

            printed++;

        } else if (res == 0) {
            // Timeout: silently ignore and continue
        } else if (res == -1) {
            cerr << "Capture error: " << pcap_geterr(handle) << endl;
            break;
        } else if (res == -2) {
            cout << "No more packets" << endl;
            break;
        }
    }


    pcap_close(handle);
    return 0;  // Return 0 signals successful program termination to the operating system
}