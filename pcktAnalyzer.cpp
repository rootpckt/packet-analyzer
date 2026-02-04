#include <iostream>    // Provides input/output stream objects like std::cout for printing to console
#include <ctime>       // Contains definitions for time-related functions and types (e.g., time_t, tm, localtime)
#include <sys/time.h>  // Defines timeval struct and gettimeofday() for high-resolution time retrieval
#include <pcap.h>      // Declares libpcap functions/types for packet capture (e.g., pcap_lookupdev)

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

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 1) {
            cout << "Captured bytes: " << header->caplen << endl;
            cout << "Original length: " << header->len << endl;
            break;
        } else if (res == 0) {
            cout << "Waiting for packet..." << endl;
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
