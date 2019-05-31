The first phase of D-TIME is creation of chunks by splitting the malware executable.
We have adopted the _splitter_ from malWASH (developed by Ispoglou and Payer).


### How to use
The splitter is an IDA-Pro plugin which will split the malware executable. Follow the steps carefully to avoid any confusions.
1. Create following directory structure in you system:  

       source
          |------dir1
                  |------dir2
                  |------malWASH_intr
                  
2. Create two files `code_1` and `code_1` under `malWASH_intr`. You may leave them empty.
3. Copy your malware executable (say `malware.exe`) to `dir2`.
4. Copy the plugin (`output/splitter.plw`) to your IDA Pro plugin directory.
5. Open `malware.exe` in IDA Pro
6. Run splitter using <kbd>Alt</kbd> + <kbd>S</kbd>.
   Provide following options in the splitter window:
      1. Select the entry block  
         Entry block is the first block of malware
      2. Select a splitting algorithm  
      3. The `Inject malWASH engine in` option is not important, you may set any value  
         We will override this in our emulator
      4. Under Additional options, tick `Do not delete temporary files`
      5. If your malware use `WinMain` instead of `main`, select `WinMain`
      6. Provide commandline arguments if any
      7. Click OK
      
