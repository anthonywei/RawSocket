#!/bin/sh
OBJ1=fakeping
OBJ2=sniffer
default:
	gcc -o $(OBJ1) $(OBJ1).c
	gcc -o $(OBJ2) $(OBJ2).c
clean:
	rm -fr $(OBJ1) $(OBJ2) 
