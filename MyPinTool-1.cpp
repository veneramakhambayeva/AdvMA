#include "pin.H" 
#include <iostream> 
#include <fstream> 
#include <stdlib.h> 

void* prev;
bool check = true;
using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "imageload.out", "specify file name"); 

ofstream TraceFile; 

VOID print(VOID* ip, string* s) {
	//void* prev = ip;
	if (check == true) {
		check = false;
		prev = ip;
		TraceFile << "digraph controlflow {" << endl;
	}
	else {
		TraceFile << "\"" << std::hex << ip << "\"" << " -> \"" << std::hex << prev << "\";" << endl;
		//TraceFile << prev << endl;
		prev = ip;
	}
}

VOID ImageLoad(IMG img, VOID *v) 
{ 
	if (IMG_IsMainExecutable(img)) { 
		TraceFile << IMG_Name(img) << endl; 
	    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) 
	    { 
			if(SEC_IsExecutable(sec)) 
	{ 
				//TraceFile << "Address: " << std::hex << SEC_Address(sec) << endl; 
	for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) { 
		RTN_Open(rtn); 
		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) { 
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)print, IARG_INST_PTR, IARG_PTR, new string(INS_Disassemble(ins)),IARG_END);
			//TraceFile << IPOINT_BEFORE << " "<<IARG_INST_PTR << "  "<<IARG_PTR<<"\n";
		} 
		RTN_Close(rtn); 
	} 
			} 
			//else TraceFile << "Address: " << std::hex<< SEC_Address(sec) << " SEC_name " << SEC_Name(sec) << endl; 
		} 
	} 
} 
// This function is called when the application exits 
  // It closes the output file. 
VOID Fini(INT32 code, VOID *v) 
{ if (TraceFile.is_open()) { TraceFile.close(); } 
} /* ===================================================================== */ /* Print Help Message */ /* ===================================================================== */ 
INT32 Usage() 
{ 
	PIN_ERROR("This tool prints a log of image load and unload events\n" + KNOB_BASE::StringKnobSummary() + "\n"); 
	return -1; 
} /* ===================================================================== */ /* Main */ /* ===================================================================== */ 
int main(int argc, char * argv[]) 
{ 
	// Initialize symbol processing 
	PIN_InitSymbols(); 
	// Initialize pin 
	if (PIN_Init(argc, argv)) return Usage(); 
	TraceFile.open(KnobOutputFile.Value().c_str()); 
	// Register ImageLoad to be called when an image is loaded 
	IMG_AddInstrumentFunction(ImageLoad, 0); 
	// Register Fini to be called when the application exits 
	PIN_AddFiniFunction(Fini, 0); 
	// Start the program, never returns 
	PIN_StartProgram(); 
	return 0; }

