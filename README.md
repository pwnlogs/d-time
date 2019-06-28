# D-TIME
__D-TIME: Distributed Threadless Independent Malware Execution for Runtime Obfuscation__

An important aspect of malware design is to be able to evade detection. This is increasingly difficult to achieve with pow erful runtime detection techniques based on behavioural and heuristic analysis. In this paper, we propose D-TIME, a new distributed threadless independent malware execution frame work to evade runtime detection.

D-TIME splits a malware executable into small chunks of instructions and executes one chunk at a time in the context of an infected thread. It uses a Microsoft Windows feature called Asynchronous Procedure Call (APC) to facilitate chunk invocation; shared memory to coordinate between chunk executions; and a novel Semaphore based Covert Broadcasting Channel (SCBC) for communication between various chunk executions. The small size of the chunks along with the asynchronous nature of the execution makes runtime detection difficult, while the coordinated execution of the chunks leads to the intended malign action. D-TIME is designed to be self-regenerating ensuring high resilience of the system.

We evaluate D-TIME on a Microsoft Windows system with six different malware and demonstrate its undetectability with 10 different anti-virus software. We also study the CPU usage and its influence on Performance Counters.


### Directory and details

| Directory  |    Content                                                                                     |
|------------|:-----------------------------------------------------------------------------------------------|
| PoCs       | Independent PoCs for major concepts used (for covert channel and Re-generating Emulators)      |
| emualtor   | The code for emulator and a sample injection code                                              |
| samples    | 6 malware samples to test D-TIME in your environment                                           |
| splitter   | The code for IDA-Pro plugin which will split the malware                                       |

Description to each module is given in the README of respective directory.


### How to use

> **DISCLAIMER: All the content provided on this site are for educational purposes only. The site is no way responsible for any misuse of the information**

Detailed instructions for each of the following steps are given in the relevent directories. 
#### Offline Phase  
In Offline Phase, we create chunks that has to be distributed across threads. For this,
   1. Build one of our malware samples.
   1. Now we can use the malware binary and create malware chunks using `splitter`.
      `splitter` creates the chunks and write them to seperate files.
      
#### Online Phase
In the Online Phase, we inject the emulator to threads and execute malware chunks in a distributed fashion. `emulator` contains instructions to build the emulator along with a sample injector which will inject the emulators for you.
   1. Build the `emulator`.
   2. Copy the chunk files to your working directory for emulator.
   3. Run the `emulator.exe`.  
   The `emulator.exe` contains the  actual emulator code and a sample injector. It will:
       1. Read your chunks from the working directory and store them in shared memory
       2. Inject the emulator to victim processes.
       3. Exit  
       The injected emulator will now execute the chunks and re-generate themselves to execute more chunks.
