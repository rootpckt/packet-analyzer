#include "library.h"
#include <iostream>
#include <ctime>
#include <sys/time.h>
using namespace std;


int main() {


    /*
     timeval  → raw time container
               stores time as seconds + microseconds since 1 Jan 1970 (epoch).
               This is machine format (not human readable).

     tm       → human time container
               stores broken-down time like hour, minute, second, day, month, year.
               This is human readable format.

     Flow:
     kernel time → timeval → seconds → localtime() → tm → print
    */

    timeval ts;   // Raw time container: holds epoch time (machine format)
    gettimeofday(&ts, nullptr);   // Kernel writes current real time into ts

    time_t seconds = ts.tv_sec;   // Extract raw seconds from timeval

    tm* timeinfo = localtime(&seconds);   // Convert raw seconds → human-readable time (tm struct)

    // Read fields from tm struct and print real human time
    cout << "Time: "
    << (*timeinfo).tm_hour << ":"
    << timeinfo -> tm_min << ":"
    << timeinfo -> tm_sec << endl;

// $whoami?root@99$ $whoami?root@99$ $nobodyKNOWSboutfSOCIETY@99$ $nobodyKNOWboutfSOCIETY99@$ $nobodyKNOWboutfSOCIETY@99$

    return 0;
}