# NetworkSystems_PA4

## Distributed file systems
  * seperate one file to four pieces and store them in four different remote servers
  * Each server store two piece of each files so even if one server is down, the file can still be created
  * Handle multiple users
  * Implemented commands:
    * LIST, PUT, GET, MKDIR
## Instruction
  * open four terminal and run 
    * `./1server`
    * `./2server`
    * `./3server`
    * `./4server`
  *  open one more terminal and run either\
    * `./aliceclient.sh` or `./bobclient.sh`
