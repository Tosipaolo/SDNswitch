# SDNswitch

## HOPBYHOPHANDLER
- based on a barebone implementation of a Ryu Hop-by-Hop configuring network;
- The network saves the path used by the active flows in a data structure. If a new dicovered path includes a smaller
  already present one, the latter will be counted inside the longer one;
- In case of a link brakage (triggered through the mininet command line inteface) the network will be aware of that.  
  In this case the topology is refreshed, and the controller verifies which path are affected by the breakage.
- Flowtable entries on the unreachable side of the net are deleted, while the ones for smaller non-affected path are kept.
- On a new transmission the controller will indicate a new shortest path from client to server if available, or indicate the unreachability.

## Hbhconrest
- basato su switch2.py
- usa la rest api
- fa match su campi eth-dst eth-src dei flussi che passano per la porta modificata
- invia messaggi FlowMod a tutti gli switch ed elimina i flussi tra src e dst interessate
- non funziona con hop-by-hop

## Hbhnorest 
- hop-by-hop approach without getting the tables from the REST API, not working
- It's not saving all conversations betwen the hosts.


