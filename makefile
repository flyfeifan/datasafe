rsa_dir = ./rsa
objects:= interface.o interface_wrap.o data_rsa.o

_datasafe.so : ${objects}
	g++ -shared ${objects} -o _datasafe.so

interface.o : interface.cpp 
	g++ -I${rsa_dir} -c interface.cpp

interface_wrap.o : interface_wrap.cxx
	g++ -I/usr/include/python2.6 -I${rsa_dir} -c interface_wrap.cxx

interface_wrap.cxx : interface.i 
	swig -python -c++ interface.i

data_rsa.o : ${rsa_dir}/data_rsa.cpp 
	g++ -I${rsa_dir} -c ${rsa_dir}/data_rsa.cpp

VPARTH += ./rsa

clean:
	rm -f *.py 
	rm -f *.o
	rm -f *.so
	rm -f *.cxx
	rm -f *.pyc
	rm -f *~
