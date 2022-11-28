all: drvtest
clean:
	rm -f drvtest
drvtest: drvtest.c
	gcc -g -Iinclude -O0 -o $@ $^

rowhammer-skylake-norm: rowhammer.cc
	g++ -g -pthread -Iinclude -std=c++11 -O0 -o $@ -DNORM $^
rowhammer-skylake-spec-double: double_sided_rowhammer.cc
	g++ -g -pthread -Iinclude -std=c++11 -O0 -o $@ $^
rowhammer-skylake-spec: rowhammer.cc
	g++ -g -pthread -Iinclude -std=c++11 -O0 -o $@ -DSPEC $^

