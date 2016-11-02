from __future__ import print_function
import sys
import os
import subprocess
import time
from datetime import datetime
import re

"""
rr_parseomater.py

Author
    David Pany
    Mandiant (FireEye) 2016
    Twitter: @DavidPany

Current Version
    1.1
    
ChangeLog
    1.1
        [x] Minor bug where user account name was very long in file header
        [x] MasterTimeline extension changed to .xls (it's a TSV file)
    
Description
    rr_parseomater.py wraps around RegRipper's (https://github.com/keydet89/RegRipper2.8)
    rip.exe executable to easily parse and timeline all NTUSER.DAT, USRCLASS.DAT, and 
    S-Registry files (SAM, SOFTWARE, SECURITY, SYSTEM).
    
    Features include
        - removes plugin results with no findings for easy to read results
        - extracts username from NTUSER hive and appends to output file name
        - creates a timeline for each hive and one master timeline for analysis
    
USAGE
    1. Extract all NTUSER.DAT files to a folder such as "registryfiles/ntuser"
    2. Extract all USRCLASS.DAT files to a folder such as "registryfiles/usrclass"
    3. Extract SAM, SOFTWARE, SECURITY, and SYSTEM files to a folder such as "registryfiles/sregistry"
    4. Create an output reports directory such as "registryfiles/reports"
    4. Place rr_parseomater.py in RegRipper directory (same directory as rip.exe)
    
    5. Execute with appropriate directory paths (in this order):
        rr_parseomater.py registryfiles/ntuser registryfiles/usrclass registryfiles/sregistry registryfiles/reports

TODO
    [ ] find a new timeline technique that will add values' data to the timeline
    [ ] Add proper argument handling and help menu

"""

def TimestampLineConvert(line,filename):
    #Convert RR timestamp format to YYYY-MM-DD HH:MM:SS UTC
    
    Timestamp = line[:24]
    if Timestamp[:3] in ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]:
        TimeOb = time.strptime(Timestamp)#,"%a %b %d %H:%M:%S %Y")
        ConvertedLine = "{}-{}-{} {}:{}:{} \t{}{}".format(TimeOb.tm_year,TimeOb.tm_mon,TimeOb.tm_mday,TimeOb.tm_hour,TimeOb.tm_min,TimeOb.tm_sec,filename,line[27:-1])
        return ConvertedLine
    else:
        return None

def IsRegistry(FilePath):
    #Check the file header to ensure it is a registry file
    
    try:
        with open(FilePath,"r") as f:
            header = f.read(4)
            if header == "regf":
                return True
            else:
                return False
    except IOError:
        return False
            
def RunRegRipper(FilePath,file,profile,ReportDir,username=None):
    #Run RR's rip.exe as a subprocess and remove "no finding" plugin results
    
    Output = subprocess.check_output("""rip.exe -r "{}" -f {}""".format(FilePath,profile))
    if username:
        OutputFileName = "{}\{}_{}.txt".format(ReportDir,file,username)
    else:
        OutputFileName = "{}\{}.txt".format(ReportDir,file)
    OutputFile = open(OutputFileName,"w")
    for Line in Output.split("\n"):
        OutputFile.write(Line)
    OutputFile.close()
    CleanFile(OutputFileName)
    
def RunTimelinePy(FilePath,file,ReportDir,username=None):
    #Run RR's regtime plugin to create a timeline output file and store the timeline in the 
    # MasterTimeline set
    Timeline = subprocess.check_output("""rip.exe -r {} -p regtime""".format(FilePath))
    if username:
        TimelineFile = open("{}\{}_{}_timeline.txt".format(ReportDir,file,username),"w")
    else:
        TimelineFile = open("{}\{}_timeline.txt".format(ReportDir,file),"w")
    TempTimeline = set()
    for Line in Timeline.split("\n"):
        if Line[:3] in ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']:
            Line = TimestampLineConvert(Line,file)
        TimelineFile.write("{}\n".format(Line))
        TempTimeline.add(Line)
    TimelineFile.close()
    return TempTimeline

def GetRegUsername(filename):
    #Extract username from partial file path in beginning of reg files if available
    usernameMO = re.compile("([^a-z0-9\ \.]*)(\\\\NTUSER)", re.IGNORECASE)
    
    handle = open(filename)
    string = handle.read(300).replace("\x00","")
    
    usernameMatch = re.search(usernameMO, string)
    try:
        return usernameMatch.groups()[0]
    except AttributeError:
        return None
    handle.close()		
    
def CleanFile(filename):
    #Remove "no finding" plugin results from the ouput text files
    
    inputFile = open(filename,"rb")
    inputText = inputFile.readlines()[0].replace("\r","\r\n").split("----------------------------------------")
    inputFile.close()
    outputFile = open(filename,"wb")
    for i in inputText:
        if ("not found" in i or "not exist" in i) and i.count("\r\n") <= 7:
            pass
        else:
            outputFile.write(i)
            outputFile.write("----------------------------------------")
    print(len(inputText))

def main():
    #Clean up input directories
    NtuserDir = sys.argv[1].replace('"','')
    UsrClassDir = sys.argv[2].replace('"','')
    SRegDir = sys.argv[3].replace('"','')
    ReportDir = sys.argv[4].replace('"','')
    
    #Create MasterTimeline set
    MasterTimeline = set()
    
    #parse NTUSER.DAT files
    for file in os.listdir(NtuserDir):
        FilePath = os.path.join(NtuserDir,file)
        if IsRegistry(FilePath):
            print("Parsing {}".format(FilePath))
            RunRegRipper(FilePath,file,"ntuser",ReportDir,GetRegUsername(FilePath))
            print("Timelining {}".format(FilePath))
            MasterTimeline = MasterTimeline.union(RunTimelinePy(FilePath,file,ReportDir,GetRegUsername(FilePath)))

    #parse UsrClass.Dat files
    for file in os.listdir(UsrClassDir):
        FilePath = os.path.join(UsrClassDir,file)
        if IsRegistry(FilePath):
            print("Parsing {}".format(FilePath))
            RunRegRipper(FilePath,file,"usrclass",ReportDir)
            print("Timelining {}".format(FilePath))
            MasterTimeline = MasterTimeline.union(RunTimelinePy(FilePath,file,ReportDir))
           
    #Parse Sregistry files
    for file in os.listdir(SRegDir):
        FilePath = os.path.join(SRegDir,file)
        if IsRegistry(FilePath):
            print("Parsing {}".format(FilePath))
            RunRegRipper(FilePath,file,file,ReportDir)
            print("Timelining {}".format(FilePath))
            MasterTimeline = MasterTimeline.union(RunTimelinePy(FilePath,file,ReportDir))
    
    #Create a master timeline output file in TSV format
    MasterTimelineFile = open("{}\MasterTimeline.xls".format(ReportDir),"w")  
    MasterTimelineFile.write('"Time"\t"Path"\n')
    for entry in MasterTimeline:
        if len(entry) > 20 and "(All) Dumps entire hive" not in entry:
            MasterTimelineFile.write("{}\n".format(entry))
    MasterTimelineFile.close()

main()
