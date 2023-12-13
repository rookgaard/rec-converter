#pragma once
#include <windows.h>

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

WORD GuessVersion(CONST BYTE version, CONST BYTE encryption) {
	switch (version) {
	case 3:	switch (encryption) {
	case 1:	return 721;
	case 2: return 730;
	}
	case 4: return 770;
	case 5: return 772;
	case 6: return 800;
	}
	return 800;
}

const char* get_filename_ext(const char* filename) {
	const char* dot = strrchr(filename, '.');
	if (!dot || dot == filename) return "";
	return dot + 1;
}

std::string string_to_hex(const std::string& input)
{
	static const char hex_digits[] = "0123456789ABCDEF";

	std::string output;
	output.reserve(input.length() * 2);
	for (unsigned char c : input)
	{
		output.push_back(hex_digits[c >> 4]);
		output.push_back(hex_digits[c & 15]);
	}
	return output;
}
