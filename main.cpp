#include <iostream>
#include <string>
#include <cstdint>
#include "PCAP.h"


using namespace std;

struct PCAPFile {
    string fileName;
    uint64_t packetsCount;
    uint64_t payloadSize;

	PCAPFile(string name, uint64_t packets, uint64_t size) : 
		fileName(name), packetsCount(packets), payloadSize(size) {}
};

int main ()
{
	PCAPFile input1("examples\\PPP-config.pcap",        22,  1538); 
	PCAPFile input2("examples\\rtp-norm-transfer.pcap", 226, 294586); 
	PCAPFile input3("examples\\nlmon-big.pcap",         13,  10356);

	PCAPReader parser1(input1.fileName);
	PCAPReader parser2(input2.fileName);
	PCAPReader parser3(input3.fileName);

	if (parser1.packetsCount() == input1.packetsCount) 
		cout << "the first packets are equals" << endl;
	else cout << "the first packets are NOT equals" << endl;

	if (parser2.packetsCount() == input2.packetsCount) 
		cout << "the second packets are equals" << endl;
	else cout << "the second packets are NOT equals" << endl;

	if (parser3.packetsCount() == input3.packetsCount) 
		cout << "the third packets are equals" << endl;
	else cout << "the third packets are NOT equals" << endl;

	if (parser1.payloadSize() == input1.payloadSize)
		cout << "the first bytes are equals" << endl;
	else cout << "the first bytes are NOT equals" << endl;

	if (parser2.payloadSize() == input2.payloadSize)
		cout << "the second bytes are equals" << endl;
	else cout << "the second bytes are NOT equals" << endl;

	if (parser3.payloadSize() == input3.payloadSize)
		cout << "the third bytes are equals" << endl;
	else cout << "the third bytes are NOT equals" << endl;


    return 0;
}