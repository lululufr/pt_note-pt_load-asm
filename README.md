# tp_note-tp_load-asm

Lucas MILLER 3SI4

Ce projet est un programme d'infection d'ELF à travers la méthode pt note to pt load. 


IL n'est PAS nécéssaire de désactiver l'ASLR. 
Ce programme est dynamique et ne nécéssite donc pas de modifier le code lors de l'utilisation sur un autre programme. 
Une fois infecté le programme va lors de son lancement éxécuter un revers shell. 
L'IP peut etre choisis lors du lancement, mais le port sera toujours 4444. 



il fonctionne sur les ELF avec les arguments -no-pie. 

```
gcc -no-pie ../saine-code/safe_code.c -o ../saine-code/safe_code
```


IL se compile ainsi : 
```
nasm -f elf64 -o pt_note_to_pt_load_infector.o pt_note_to_pt_load_infector.s && ld -o pt_note_to_pt_load_infector pt_note_to_pt_load_infector.o
```

il va infecter le programme donné en argument 

```
./pt_note_to_pt_load_infector ../saine-code/safe_code
```