# SDNswitch

## HOPBYHOPHANDLER
- basato su switch5, Hop by hop
- salvataggio dei path utilizzati dalle conversazioni (se più piccoli vengono inglobati dai più lunghi)
- individua il link rotto e verifica quali path siano colpiti
- eliminazione delle flowtable sulla parte del path che non può più raggiungere l'host di destinazione
- la tabella dei path è aggiornata eliminando il path più lungo e mantenendo la parte funzionante


## Hbhconrest
- basato su switch2.py
- usa la rest api
- fa match su campi eth-dst eth-src dei flussi che passano per la porta modificata
- invia messaggi FlowMod a tutti gli switch ed elimina i flussi tra src e dst interessate
- non funziona con hop-by-hop

## Hbhnorest 
- basato su switch5, hop by hop switch
- utilizza struttura dati per tenere conto dei flussi su ogni porta di ogni switch
- utilizza le funzioni di NX per trovare il percorso tra gli host che comunicano 
  attraverso la porta interessata
- invia messaggi di FlowMod a tutti gli switch che si trovano sul percorso tra i due host
- NON FUNZIONANTE: NON SALVA TUTTE LE CONVERSAZIONI TRA HOST, NON MANTIENE TUTTO FUNZIONANTE

