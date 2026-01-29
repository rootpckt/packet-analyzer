#include "library.h"
#include <ctime>
#include <iostream>
#include <sys/time.h>
using namespace std;



void printCurrentTime() {
    timeval ts;
    gettimeofday(&ts, nullptr);

    time_t seconds = ts.tv_sec;
    tm* timeinfo = localtime(&seconds);

    cout << "Time: "
         << timeinfo->tm_hour << ":"
         << timeinfo->tm_min << ":"
         << timeinfo->tm_sec << endl;
}
