%module interface
%include "std_string.i"
%apply std::string &OUTPUT { std::string &dstdata,std::string &privatekeyout, std::string& publickeyout };

%{
#include "interface.h"
%}

%include "interface.h"
