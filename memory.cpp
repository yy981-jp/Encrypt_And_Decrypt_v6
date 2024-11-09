#include <windows.h>
#include <thread>
#include <chrono>


int getMemoryUsage() {
    // メモリ情報を格納する構造体
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);

    // メモリ情報を取得
    if (GlobalMemoryStatusEx(&memInfo)) {
        DWORDLONG totalPhysMem = memInfo.ullTotalPhys;
        // DWORDLONG physMemUsed = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
        double memoryUsagePercentage = (double)memInfo.ullAvailPhys / (double)totalPhysMem * 100.0;  // 100-使用率
		return static_cast<int>(memoryUsagePercentage);
    } else {
		return -1;
    }
}

int main() {
	std::thread([]{while(true) new long double;}).detach();
	while(true) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
		if (getMemoryUsage()<=3) return 0;
	}
}