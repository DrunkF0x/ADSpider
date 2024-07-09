```
                                                                                         (
       d8888 8888888b.   .d8888b.           d8b      888                                  )
      d88888 888  "Y88b d88P  Y88b          Y8P      888                                 ( 
     d88P888 888    888 Y88b.                        888                           /\  .-"""-.  /\ 
    d88P 888 888    888  "Y888b.   88888b.  888  .d88888  .d88b.  888d888         //\\/  ,,,  \//\\ 
   d88P  888 888    888     "Y88b. 888 "88b 888 d88" 888 d8P  Y8b 888P"           |/\| ,;;;;;, |/\| 
  d88P   888 888    888       "888 888  888 888 888  888 88888888 888             //\\\;-"""-;///\\ 
 d8888888888 888  .d88P Y88b  d88P 888 d88P 888 Y88b 888 Y8b.     888            //  \/   .   \/  \\ 
d88P     888 8888888P"   "Y8888P"  88888P"  888  "Y88888  "Y8888  888           (| ,-_| \ | / |_-, |) 
                                   888                                            //`__\.-.-./__`\\ 
                                   888                                           // /.-(() ())-.\ \\ 
                                   888                                          (\ |)   "---"   (| /) 
                                                                                 ` (|           |) ` 
                                                             By DrunkF0x.          \)           (/
```

Tool for monitor Active Directory changes in real time without getting all objects.
Instead of this it use replication metadata and Update Sequence Number (USN) to filter current properties of objects.

## Parameters
**DC** - domain controller FQDN.  
**Formatlist** - output in list instead of table.  
**ExcludelastLogonTimestamp** - exclude lastLogonTimestamp events from output  
**DumpAllObjects** - dump all active directory before start. In case of changes It will show you all previous values. But in large domains use it on your own risk (time and resource consuming).    
**Short** - in output will be only AttributeName, AttributeValue, LastOriginChangeTime and Explanation.  
**Output** - create XML file with all output.    
**ExcludeObjectGUID** - exclude Active Directory object with specific GUID.  
**Sleep** - time interval between requests for USN number. By default - 30 seconds.  
**USN** - specify started USN.   
**DisplayXML** - display previous captured XML file.  
## How to use
### Domain computer
Just run module in powershell session from domain user. For better performance use domain controller FQDN instead of IP address.
```powershell
Import-module .\ADSpider.ps1
Invoke-ADSpider -DC DC01.domain.com
```
### Non-domain computer
Start powershell session with domain user with runas. Check that domain controller accessible. For better performance use domain controller FQDN instead of IP address.
```powershell
## From cmd or powershell
runas /netonly /u:domain.com\MyUser powershell
## From powershell
Import-module .\ADSpider.ps1
Invoke-ADSpider -DC DC01.domain.com
```

## Interesting links
https://premglitz.wordpress.com/2013/03/20/how-the-active-directory-replication-model-works/
https://learn.microsoft.com/en-us/archive/technet-wiki/51185.active-directory-replication-metadata  
https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags   
https://learn.microsoft.com/en-us/windows/win32/ad/linked-attributes     
