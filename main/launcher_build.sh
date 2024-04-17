#!/bin/bash
nasm -f elf64 -o tp_note_to_tp_load.o tp_note_to_tp_load.s && ld -o tp_note_to_tp_load tp_note_to_tp_load.o && ./tp_note_to_tp_load
