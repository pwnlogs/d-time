/*
		PoC to test life-time of Semaphore based Covert Channel.
*/

#include <Windows.h>
#include <iostream>

#define semName "testSemaphore"
#define mtxName "testMutex"

using namespace std;

void __stdcall create(ULONG_PTR parameter) {
	LONG max_value = 0x1234;
	LONG init_value = max_value;
	HANDLE mtx = CreateMutexA(NULL, TRUE, mtxName);
	if (mtx == NULL) {
		cout << "[!] Failed to create Mutex" << endl;
		return;
	}
	cout << "[+] Created and Owned Mutex" << endl;

	HANDLE sem = CreateSemaphoreA(NULL, init_value, max_value, semName);
	if (sem != NULL) {
		cout << "[+] Created Semaphore succesfully from Thread: " << GetCurrentThreadId() << endl;
		cout << "[i] Semaphore count: " << init_value << endl;
		cout << "[i] Semaphore max-count: " << max_value << endl;
	}
	else {
		cout << "[!] Failed to create Semaphore" << endl;
	}

	if (ReleaseMutex(mtx)) {
		cout << "[+] Released Mutex" << endl;
	}
	else {
		cout << "[!] Failed to release Mutex" << endl;
	}
	return;
}


void __stdcall check(ULONG_PTR parameter) {
	HANDLE sem = OpenSemaphoreA(SEMAPHORE_ALL_ACCESS, FALSE, semName);
	if (sem != NULL) {
		cout << "[+] Semaphore opened from Thread: " << GetCurrentThreadId() << endl;
		LONG prev_count = 0;

		HANDLE mtx = OpenMutex(MUTEX_ALL_ACCESS, FALSE, mtxName);
		if (mtx != NULL) {
			cout << "[+] Opened mutex successfully " << endl;
		}
		else {
			cout << "[!] Failed to create Mutex" << endl;
			return;
		}
		if (WaitForSingleObject(mtx, 1000) != WAIT_OBJECT_0) {
			cout<<"[!] Could not lock mutex"<<endl;
			return;
		}
		else {
			cout << "[+] Locked mutex successfully" << endl;
		}

		cout << "[+] Decreamenting semaphore count" << endl;
		DWORD wait = WaitForSingleObject(sem, 0);
		if (wait != WAIT_OBJECT_0) {
			cout << "[!] Decrement might have failed" << endl;
		}
		else {
			cout << "[+] Semaphore wait success" << endl;
		}

		int success = ReleaseSemaphore(sem, 1, &prev_count);
		cout << "[+] Attempted release of semaphore" << endl;
		cout << "[i] Prev-count: " << prev_count << endl;
		cout << "[i] Success: " << (success!=0 ? "True" : "False") << endl;

		if (ReleaseMutex(mtx)) {
			cout << "[+] Released mutex" << endl;
		}
	}
	return;
}

DWORD __stdcall threadFn(LPVOID parameter) {
	for(int i=0; i<2; ++i){
		SleepEx(1000, TRUE);
	}
	cout << "[+] Exiting thread " << GetCurrentThreadId() << endl;
	return 0;
}



void main() {

	/* create first victim thread for APC injection */
	DWORD threadId;
	HANDLE thread1 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadFn, 0, 0, &threadId);
	cout << "\n[i] First ThreadId: " << threadId << endl;
	/* Queue user apc in first thread */
	QueueUserAPC(create, thread1, NULL);

	Sleep(4000);
	cout << "\n[+] Starting checker thread"<<endl;
	/* create second victim thread for APC injection */
	HANDLE thread2 = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadFn, 0, 0, &threadId);
	cout << "\n[i] Second ThreadId: " << threadId << endl;
	/* Queue user apc in second thread */
	QueueUserAPC(check, thread2, NULL);
	cin.get();

	return;
}