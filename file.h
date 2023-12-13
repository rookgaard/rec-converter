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

const char* get_filename_ext(const char* filename) {
	const char* dot = strrchr(filename, '.');
	if (!dot || dot == filename) return "";
	return dot + 1;
}
