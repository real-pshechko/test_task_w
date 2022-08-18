#include "PCAP.h"
#include <string>
#include <fstream>


typedef struct pcap_hdr_s 
{
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} pcap_hdr_t;


typedef struct pcaprec_hdr_s 
{
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} pcaprec_hdr_t;


PCAPReader::PCAPReader(const std::string &fileName) : m_fileName(fileName)
{
}


PCAPReader::~PCAPReader()
{
}


uint64_t PCAPReader::packetsCount() const
{
	int packets = 0;

	std::ifstream file (m_fileName, std::ios::binary);

	if (file == NULL) 
	{
        printf("Error opening: %s\n");
        return 1;
    }

	uint32_t magNum = 0;
	file.read((char*)&magNum, sizeof(uint32_t)); // Определяем порядок байт, если будет обратный - потом повернем

	pcap_hdr_t globalHeader;
	file.read((char*)&globalHeader, 24); // Допроходим остальные данные в Global Header
	
	pcaprec_hdr_t packetHeader;

	while (!file.eof())
	{
		
		file.read((char*)&packetHeader, 16); // Проходим Record (Packet) Header

		if (magNum == 0xd4c3b2a1) 
		{
			packetHeader.incl_len =
			((packetHeader.incl_len >> 24) & 0x000000FFul) |
			((packetHeader.incl_len >> 8)  & 0x0000FF00ul) |
			((packetHeader.incl_len << 8)  & 0x00FF0000ul) |
			((packetHeader.incl_len << 24) & 0xFF000000ul);
		}

		file.ignore(packetHeader.incl_len); // Пропускаем данные в Record (Packet) Header
		++packets;
	}

	return packets;
}


uint64_t PCAPReader::payloadSize() const
{
	int size = 0;
  
	std::ifstream file (m_fileName, std::ios::binary);

	if (file == NULL) 
	{
        printf("Error opening: %s\n");
        return 1;
    }

	uint32_t magNum = 0;
	file.read((char*)&magNum, sizeof(uint32_t)); // Определяем порядок байт, если будет обратный - потом повернем

	pcap_hdr_t globalHeader;
	file.read((char*)&globalHeader, 24); // Допроходим остальные данные в Global Header
	
	pcaprec_hdr_t packetHeader;

	while (!file.eof())
	{
		
		file.read((char*)&packetHeader, 16); // Проходим Record (Packet) Header

		if (magNum == 0xd4c3b2a1) 
		{
			packetHeader.incl_len =
			((packetHeader.incl_len >> 24) & 0x000000FFul) |
			((packetHeader.incl_len >> 8)  & 0x0000FF00ul) |
			((packetHeader.incl_len << 8)  & 0x00FF0000ul) |
			((packetHeader.incl_len << 24) & 0xFF000000ul);
		}

		file.ignore(packetHeader.incl_len); // Пропускаем данные в Record (Packet) Header
		size += packetHeader.incl_len;
	}


	return size;
}

