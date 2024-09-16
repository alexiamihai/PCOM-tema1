TEMA 1 - PCOM
DATAPLANE ROUTER

Acest proiect reprezinta un router simplu implementat in limbajul C, capabil sa
dirijeze pachete IPv4 si sa gestioneze protocolul ARP. Implementarea se bazeaza
pe o tabela de rutare statica si o tabela ARP dinamica, cu functionalitati
precum imbunatatirea cautarii cu cea mai lunga potrivire folosind un trie si
utilizarea unei cozi pentru gestionarea pachetelor in asteptare in timpul procesului ARP.

Functionalitati implementate:

Procesul de dirijare (30p): Implementarea procesului de dirijare IPv4,
utilizand o tabela de rutare statica. Am realizat pasii din laboratorul 4.

Longest Prefix Match eficient (16p): Pentru imbunatatirea eficientei cautarii
LPM, am implementat o structura de trie pentru a reduce timpul de cautare. Am folosit
2 functii, una pentru inserarea in trie si una pentru cautarea rutei.

Protocolul ARP (33p): Implementarea protocolului ARP pentru rezolvarea adreselor
MAC ale destinatiilor din retea. Am implementat si functionalitatea de caching
a adreselor MAC obtinute prin ARP, folosind o noua tabela ARP dinamica si o coada
pentru gestionarea pachetelor in asteptare in timpul procesului ARP.

Protocolul ICMP (21p): Implementarea procesarii pachetelor ICMP, inclusiv
gestionarea mesajelor ICMP echo request si trimiterea unor mesaje ICMP de eroare
cum ar fi "destination unreachable" si "time exceeded". Pentru toate tipurile de
mesaje de eroare primite, cat si pentru mesajul de echo reply, am realizat o functie
care sa trimita pachetul icmp corespunzator.

Main: Am inceput prin a verifica tipul protocolului si in functie de
acesta, am implementat logica pentru gestionarea pachetelor IP si ARP.

Observatie: In topo.py am adaugat o linie - time.sleep(5), deoarece fara ea
rezultatele testelor mi se modificau fara sa modific ceva in cod.