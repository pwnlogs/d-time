# D-TIME
__D-TIME: Distributed Threadless Independent Malware Execution for Runtime Obfuscation__

An important aspect of malware design is to be able to evade detection. This is increasingly difficult to achieve with pow erful runtime detection techniques based on behavioural and heuristic analysis. In this paper, we propose D-TIME, a new distributed threadless independent malware execution frame work to evade runtime detection.

D-TIME splits a malware executable into small chunks of instructions and executes one chunk at a time in the context of an infected thread. It uses a Microsoft Windows feature called Asynchronous Procedure Call (APC) to facilitate chunk invocation; shared memory to coordinate between chunk executions; and a novel Semaphore based Covert Broadcasting Channel (SCBC) for communication between various chunk executions. The small size of the chunks along with the asynchronous nature of the execution makes runtime detection difficult, while the coordinated execution of the chunks leads to the intended malign action. D-TIME is designed to be self-regenerating ensuring high resilience of the system.

We evaluate D-TIME on a Microsoft Windows system with six different malware and demonstrate its undetectability with 10 different anti-virus software. We also study the CPU usage and its influence on Performance Counters.


### Directory and details

| Directory  |    Content                                                                                     |
|------------|:-----------------------------------------------------------------------------------------------|
| PoCs       | Independent PoCs for major concepts used (SCBC and Re-generating APC based Emulators)          |
| emualtor   | Sample code for emulator and an example injection technique                                    |
| samples    | Provides 6 malware samples to test D-TIME in your environment                                  |
| splitter   | The code for IDA-Pro plugin which will splits the malware into chunks                          |

Description to each module is given in the README of respective directory.


### How to use

> **DISCLAIMER: All the content provided on this site are for educational purposes only. The site is no way responsible for any misuse of the information**

__It is assumed that the reader has already gone through the research paper - _"D-TIME: Distributed Threadless Independent Malware Execution for Runtime Obfuscation"_  (to be) published in WOOT'19. Understanding of this paper is crucial to understand the following steps.__

Detailed instructions for each of the following steps are given in README of relevent directories or respective files. 

__Note:__ The following steps assume the use of _Offline Keylogger_ sample. The steps to build other samples are similar.

#### Step 1: Offline Phase  
In Offline Phase, we create chunks that will be distributed across threads in the Online Phase. For this,
   1. Build `samples/offlineKeylogger/main.cpp`
   1. Now we can use the malware binary(output of above build operation) to create malware chunks using `splitter`.
      `splitter` creates the chunks and write them to seperate files.
   1. Follow the instructions provided under `splitter` to generate these files.
      
#### Step 2: Online Phase
In the Online Phase, we inject the emulator to threads and execute malware chunks in a distributed fashion. `emulator` contains instructions to build the emulator along with a sample injector which will inject the emulators for you.
   1. Build the `emulator`.
   2. Copy the chunk files to your working directory for emulator.
   3. Run the `emulator.exe`.  
   The `emulator.exe` contains the  actual emulator code and a sample injector. It will:
       1. Read your chunks from the working directory and store them in shared memory
       2. Inject the emulator to victim processes.
       3. Exit  
       The injected emulator will now execute the chunks and re-generate themselves to execute more chunks.
