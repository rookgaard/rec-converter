#include <iostream>
#include <filesystem>
#include "file.h"
#include "aes256.h"

#define DEBUG

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

std::vector<Packet> loadRec(const std::string path)
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
			DWORD timeOffset;
			File.ReadDword(timeOffset);
#ifdef DEBUG
			fprintf(pFile, "timeOffset: %d\n", timeOffset);
			fflush(pFile);
#endif

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
				BYTE Key = packetLength + timeOffset + 2;
				fprintf(pFile, "Key 4: %d\n", packetLength + timeOffset + 2);
				fflush(pFile);
				fprintf(pFile, "Key 5: %d\n", Key);
				fflush(pFile);

				for (WORD i = 0; i < packetLength; i++) {
					fprintf(pFile, "Minus 0: %d\n", Key + 33 * i);
					fflush(pFile);
					CHAR Minus = Key + 33 * i;
					fprintf(pFile, "Minus 1: %d\n", Minus);
					fflush(pFile);

					if (Minus < 0) {
						while (-Minus % Mod) Minus++;
					}
					else {
						while (Minus % Mod) Minus++;
					}

					fprintf(pFile, "Minus 2: %d\n", Minus);
					fflush(pFile);
					fprintf(pFile, "Data 0: %d\n", packet[i]);
					fflush(pFile);
					packet[i] -= Minus;
					fprintf(pFile, "Data 1: %d\n", packet[i]);
					fflush(pFile);
				}

				fprintf(pFile, "\n\npacket:\n\n");
				for (WORD i = 0; i < packetLength; i++) {
					fprintf(pFile, "%c", packet[i]);
					fflush(pFile);
				}
				fprintf(pFile, "\n\n");

				fprintf(pFile, "\n\npacket hex:\n\n");
				for (WORD i = 0; i < packetLength; i++) {
					fprintf(pFile, "%d", packet[i]);
					fflush(pFile);
				}
				fprintf(pFile, "\n\n");

				if (version > 4) {
					//Aes256::decrypt(LPBYTE("Thy key is mine © 2006 GB Monaco"), packet, packetLength);
				}

				fprintf(pFile, "\n\npacket decrypted:\n\n");
				for (WORD i = 0; i < packetLength; i++) {
					fprintf(pFile, "%c", packet[i]);
					fflush(pFile);
				}
				fprintf(pFile, "\n\n");

				fprintf(pFile, "\n\npacket decrypted hex:\n\n");
				for (WORD i = 0; i < packetLength; i++) {
					fprintf(pFile, "%d", packet[i]);
					fflush(pFile);
				}
				fprintf(pFile, "\n\n");

				std::string packetStr(LPCSTR(packet));
				packetList.push_back(Packet(timeOffset, packet, packetLength));
			}
		}
	}
	else {
		File.ReadDword(packets);
#ifdef DEBUG
		//fprintf(pFile, "packets: %d\n", packets);
		//fflush(pFile);
#endif

		for (DWORD i = 0; i < packets; i++) {
			DWORD packetLength;
			File.ReadDword(packetLength);
#ifdef DEBUG
			//fprintf(pFile, "packetLength: %d\n", packetLength);
			//fflush(pFile);
#endif
			DWORD timeOffset;
			File.ReadDword(timeOffset);
#ifdef DEBUG
			//fprintf(pFile, "timeOffset: %d\n", timeOffset);
			//fflush(pFile);
#endif

			if (packetLength) {
				LPBYTE packet = File.Skip(packetLength);
				std::string packetStr(LPCSTR(packet));
				packetList.push_back(Packet(timeOffset, packet, packetLength));
			}
		}
	}

#ifdef DEBUG
	fprintf(pFile, "packetList: %d\n", packetList.size());
	fflush(pFile);
#endif

	return packetList;
}

void saveByn(const std::string path, std::vector<Packet> packetList)
{
	WritingFile File;
	File.Open(path.c_str(), CREATE_ALWAYS);
	File.WriteByte(0x64);
	File.WriteWord(clientVersion);

	for (int i = 0; i < static_cast<int>(packetList.size()); ++i) {
		File.WriteByte(0x65);

		if (i == 0) {
			File.WriteDword(0);
		}
		else {
			File.WriteDword(packetList[i].timeOffset - packetList[i - 1].timeOffset);
		}

		File.WriteByte(0x66);
		File.WriteDword(packetList[i].packetLength);

		File.Write(packetList[i].packet, packetList[i].packetLength);
	}

	File.WriteByte(0x63);
	File.WriteDword(packetList[packetList.size() - 1].timeOffset);
}

void saveTtm(const std::string path, std::vector<Packet> packetList)
{
	WritingFile File;
	File.Open(path.c_str(), CREATE_ALWAYS);
	File.WriteWord(clientVersion);
	File.WriteByte(0); //  host length
	File.WriteDword(packetList[packetList.size() - 1].timeOffset);

	for (int i = 0; i < static_cast<int>(packetList.size()); ++i) {
		if (i > 0) {
			File.WriteByte(0);
			File.WriteDword(packetList[i].timeOffset);
		}

		File.WriteDword(1634760036);
		File.WriteDword(packetList[i].packetLength);
		File.Write(packetList[i].packet, packetList[i].packetLength);
	}
}

int main()
{
#ifdef DEBUG
	pFile = fopen("main1.log", "w");
#endif

	for (auto&& entry : std::filesystem::recursive_directory_iterator(std::filesystem::path("."))) {
		std::string path(entry.path().string());
		std::string extension(entry.path().extension().string());
#ifdef DEBUG
		//fprintf(
		//	pFile,
		//	"file: %s, extension: %s\n",
		//	path.c_str(),
		//	extension.c_str()
		//);
		//fflush(pFile);
#endif

		if (strcmp(extension.c_str(), ".rec") == 0) {
			std::vector<Packet> packetList = loadRec(path);
			//saveByn(path + ".byn", packetList);
			saveTtm(path + ".ttm", packetList);
		}
	}
}
