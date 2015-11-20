objects:= interface.o interface_wrap.o

_interface.so : ${objects}
	g++ -shared ${objects} -o _interface.so

interface.o : interface.cpp interface.h
	g++ -c interface.cpp

interface_wrap.o : interface_wrap.cxx
	g++ -I/usr/include/python2.6 -c interface_wrap.cxx

interface_wrap.cxx : interface.i interface.h
	swig -python -c++ interface.i

clean:
	rm -f *.py 
	rm -f *.o
	rm -f *.so
	rm -f *.cxx
	rm -f *.pyc
	rm -f *~
