# Process blocker driver
Creates a quarantine folder and blocks any IO operations in it. Access is carried out only for selected processes to selected files by HRU model. IBKS, 6 semester, CSST, lab 5.

You need a WDK, Visual Studio and SDK to build this.

Path to the config file: C:\CRDriver.conf\
Example content:
```
\Users\Admin\Desktop\MBKS 5\Карантин
\Device\HarddiskVolume2\Users\Admin\Desktop\MBKS 5\ReadWrite.exe::test.txt::wr
\Device\HarddiskVolume2\Users\Admin\Desktop\MBKS 5\ReadWrite.exe::folder\test.txt::w
```
The first line is the path to the quarantine folder. Next come the lines with the following access:
`PROCESS_PATH::FILE_PATH_INSIDE_QUARANTINE_FOLDER::RW`\
Where `RW` - read\write rights for pair 'process-file'.

You need a DebugView (or similar) to debug the program.
