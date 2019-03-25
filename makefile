

install: fletch
	ln -f $< fletcher64
	ln -f $< fletcher128

fletch: fletch.c

clean:
	rm -f fletch fletcher64 fletcher128

debug: fletch.c
	gcc -g $< -o fletch
