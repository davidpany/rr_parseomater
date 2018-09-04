# rr_parseomater.py
RegRipper wrapper for simplified bulk parsing or registry hives

##Author
David Pany <br />
Mandiant (FireEye) 2016 <br />
Twitter: @DavidPany <br />

##Current Version
1.2
    
##Description
rr_parseomater.py wraps around RegRipper's (https://github.com/keydet89/RegRipper2.8) rip.exe executable to easily parse and timeline all NTUSER.DAT, USRCLASS.DAT, and S-Registry files (SAM, SOFTWARE, SECURITY, SYSTEM).
   
###Features include
* removes plugin results with no findings for easy to read results
* extracts username from NTUSER hive and appends to output file name
* creates a timeline for each hive and one master timeline for analysis
    
##USAGE
1. Extract all NTUSER.DAT files to a folder such as "registryfiles/ntuser"
2. Extract all USRCLASS.DAT files to a folder such as "registryfiles/usrclass"
3. Extract SAM, SOFTWARE, SECURITY, and SYSTEM files to a folder such as "registryfiles/sregistry"
4. Create an output reports directory such as "registryfiles/reports"
5. Place rr_parseomater.py in RegRipper directory (same directory as rip.exe)
6. Execute with appropriate directory paths (in this order):
  * rr_parseomater.py registryfiles/ntuser registryfiles/usrclass registryfiles/sregistry registryfiles/reports

##TODO
* Find a new timeline technique that will add values' data to the timeline
* Add proper argument handling and help menu
