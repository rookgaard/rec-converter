#include <iostream>
#include <filesystem>
#include "file.h"
#include "aes256.h"

//#define DEBUG

struct Packet {
	DWORD delay;
	LPBYTE packet;
	DWORD packetLength;

	Packet(DWORD delay, LPBYTE packet, DWORD packetLength) {
		this->delay = delay;
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

size_t strpos(const std::string& haystack, const std::string& needle)
{
	int sleng = haystack.length();
	int nleng = needle.length();

	if (sleng == 0 || nleng == 0)
		return std::string::npos;

	for (int i = 0, j = 0; i < sleng; j = 0, i++)
	{
		while (i + j < sleng && j < nleng && haystack[i + j] == needle[j])
			j++;
		if (j == nleng)
			return i;
	}
	return std::string::npos;
}

std::vector<Packet> loadRecording(const std::string path)
{
	std::vector<Packet> packetList;
	BufferedFile File;
	File.Open(path.c_str());
	BYTE version;
	File.ReadByte(version);
#ifdef DEBUG
	fprintf(pFile, "version: %d\n", version);
	fflush(pFile);
#endif
	BYTE encryption;
	File.ReadByte(encryption);
#ifdef DEBUG
	fprintf(pFile, "encryption: %d\n", encryption);
	fflush(pFile);
#endif
	clientVersion = GuessVersion(version, encryption);
#ifdef DEBUG
	fprintf(pFile, "clientVersion: %d\n", clientVersion);
	fflush(pFile);
#endif
	DWORD packets;
	sumTime = 0;

	if (encryption == 2) {
		File.ReadDword(packets);
		packets -= 57;
#ifdef DEBUG
		fprintf(pFile, "packets: %d\n", packets);
		fflush(pFile);
#endif
		DWORD Mod = version < 4 ? 5 : version < 6 ? 8 : 6;
#ifdef DEBUG
		fprintf(pFile, "Mod: %d\n", Mod);
		fflush(pFile);
#endif

		for (DWORD i = 0; i < packets; i++) {
			WORD packetLength;
			File.ReadWord(packetLength);
#ifdef DEBUG
			fprintf(pFile, "packetLength: %d\n", packetLength);
			fflush(pFile);
#endif
			DWORD delay;
			File.ReadDword(delay);
#ifdef DEBUG
			fprintf(pFile, "delay: %d\n", delay);
			fflush(pFile);
#endif
			sumTime += delay;

			if (!packetLength) {
				DWORD Avail;
				File.ReadDword(Avail);
#ifdef DEBUG
				fprintf(pFile, "Avail: %d\n", Avail);
				fflush(pFile);
#endif
			}
			else {
				LPBYTE packet = File.Skip(packetLength);
				DWORD Avail;
				File.ReadDword(Avail);
#ifdef DEBUG
				fprintf(pFile, "Avail: %d\n", Avail);
				fflush(pFile);
#endif
				BYTE Key = packetLength + delay + 2;

				for (WORD i = 0; i < packetLength; i++) {
					CHAR Minus = Key + 33 * i;

					if (Minus < 0) {
						while (-Minus % Mod) Minus++;
					}
					else {
						while (Minus % Mod) Minus++;
					}

					packet[i] -= Minus;
				}

				if (version > 4) {
					Aes256::decrypt(LPBYTE("Thy key is mine © 2006 GB Monaco"), packet, packetLength);
				}

				packetList.push_back(Packet(delay, packet, packetLength));
			}
		}
	}
	else {
		File.ReadDword(packets);
#ifdef DEBUG
		fprintf(pFile, "packets: %d\n", packets);
		fflush(pFile);
#endif

		for (DWORD i = 0; i < packets; i++) {
			DWORD packetLength;
			File.ReadDword(packetLength);
#ifdef DEBUG
			fprintf(pFile, "packetLength: %d\n", packetLength);
			fflush(pFile);
#endif
			DWORD delay;
			File.ReadDword(delay);
#ifdef DEBUG
			fprintf(pFile, "delay: %d\n", delay);
			fflush(pFile);
#endif
			sumTime += delay;

			if (packetLength) {
				LPBYTE packet = File.Skip(packetLength);
				packetList.push_back(Packet(delay, packet, packetLength));
			}
		}
	}

	return packetList;
}

void saveBynRecording(const std::string path, std::vector<Packet> packetList)
{
	WritingFile File;
	File.Open(path.c_str(), CREATE_ALWAYS);
	File.WriteByte(0x64);
	File.WriteWord(clientVersion);

	for (int i = 0; i < static_cast<int>(packetList.size()); ++i) {
		File.WriteByte(0x65);
		File.WriteDword(packetList[i].delay);

		File.WriteByte(0x66);
		File.WriteDword(packetList[i].packetLength);

		File.Write(packetList[i].packet, packetList[i].packetLength);
	}

	File.WriteByte(0x63);
	File.WriteDword(sumTime);
}

int main()
{
#ifdef DEBUG
	pFile = fopen("main.log", "w");
#endif

	for (auto&& entry : std::filesystem::directory_iterator(std::filesystem::path("."))) {
		std::string str(entry.path().string());
#ifdef DEBUG
		fprintf(pFile, "file: %s, found: %d\n", str.c_str(), strpos(str, ".rec"));
		fflush(pFile);
#endif

		if (strpos(str, ".rec") == std::string::npos) {
			continue;
		}

		std::vector<Packet> packetList = loadRecording(entry.path().string());
		saveBynRecording(entry.path().string() + ".byn", packetList);
	}
}
