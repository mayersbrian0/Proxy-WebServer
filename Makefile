all:
	gcc -o webproxy webproxy.c -l pthread

clean:
	-rm webproxy
    

