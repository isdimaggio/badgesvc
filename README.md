# badgesvc 

Piccolo server locale che si occupa della comunicazione PC/SC con lettori generici smart card, legge CIE, CNS e NTAG213 ed espone un interfaccia websocket per essere integrato con il registro online o i totem. 

## Installazione
- Clona la repository o scarica lo ZIP ed estrailo
- Verifica di avere Node e npm installati
- Esegui npm install per scaricare tutte le dipendenze
- Avvia il server con `node readerserver.js`

Puoi verificare il funzionamento visitando la pagina di prova a [http://127.0.0.1:25585/](http://127.0.0.1:25585/)
