all:
	gcc -o webproxy webproxy.c -l pthread -l crypto 

clean:
	-rm webproxy
	-rm -rf ./cache/*
    

