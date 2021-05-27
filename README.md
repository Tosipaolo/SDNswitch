# SDNswitch

## downhandler
- basato su switch2.py
- usa la rest api
- fa match su campi eth-dst eth-src dei flussi che passano per la porta modificata
- invia messaggi FlowMod a tutti gli switch ed elimina i flussi tra src e dst interessate
- non funziona con hop-by-hop

## handler-no-rest 
- basato su switch5, hop by hop switch
- utilizza struttura dati per tenere conto dei flussi su ogni porta di ogni switch
- utilizza le funzioni di NX per trovare il percorso tra gli host che comunicano 
  attraverso la porta interessata
- invia messaggi di FlowMod a tutti gli switch che si trovano sul percorso tra i due host


