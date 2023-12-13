#pragma once
#include <windows.h>

FILE* pFile;
WORD clientVersion;

struct Packet {
	uint32_t timeOffset;
	std::string packet;
	uint32_t packetLength;

	Packet(uint32_t timeOffset, std::string packet, uint32_t packetLength) {
		this->timeOffset = timeOffset;
		this->packet = packet;
		this->packetLength = packetLength;
	}
};
