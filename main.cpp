#include "stdafx.h"
#include <random>
#include <exception>
using namespace std;

#define DNS_A 1
#define DNS_NS 2
#define DNS_CNAME 5
#define DNS_PTR 12
#define DNS_INET 1
#define DNS_QUERY (0 << 15)
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11)
#define DNS_RD (1 << 8)
#define MAX_DNS_SIZE 512
#define MAX_DNS_NAME 1024
#define MAX_ATTEMPTS 3

#pragma pack(push, 1)
class QueryHeader {
public:
    USHORT qType;
    USHORT qClass;
};

class FixedDNSHeader {
public:
    USHORT ID;
    USHORT flags;
    USHORT questions;
    USHORT answers;
    USHORT authority;
    USHORT additional;
};

class DNSanswerHdr {
public:
    USHORT type;
    USHORT rrClass;
    UINT TTL;
    USHORT len;
};
#pragma pack(pop)

static_assert(sizeof(QueryHeader) == 4, "Question header must be 4 bytes");
static_assert(sizeof(FixedDNSHeader) == 12, "DNS header must be 12 bytes");
static_assert(sizeof(DNSanswerHdr) == 10, "RR header must be 10 bytes");

int makeQuestion(char* question, const char* host) {
    if (strcmp(host, ".") == 0) {
        question[0] = 0;
        return 1;
    }
    int hostLength = (int)strlen(host);
    if (hostLength == 0 || hostLength > 253) {
        return -1;
    }
    int questionPosition = 0;
    int labelStart = 0;
    for (int i = 0; i <= hostLength; i++) {
        if (host[i] != '.' && host[i] != '\0') {
            continue;
        }
        int labelLength = i - labelStart;
        if (labelLength == 0 || labelLength > 63) {
            return -1;
        }
        if (questionPosition + 1 + labelLength + 1 > 255) {
            return -1;
        }
        question[questionPosition] = (char)labelLength;
        questionPosition++;
        memcpy(question + questionPosition, host + labelStart, labelLength);
        questionPosition = questionPosition + labelLength;
        labelStart = i + 1;
    }
    question[questionPosition] = 0;
    questionPosition++;
    return questionPosition;
}

bool parseError(const char* message) {
    printf("  %s\n", message);
    return false;
}

bool readName(char* responseBuffer, int bytesReceived, int& nextByte, char* name, int nameEnd) {
    bool visited[MAX_DNS_SIZE] = {};
    int currentInt = nextByte;
    int nameLength = 0;
    int expandedSize = 1;
    bool hasJumped = false;
    name[0] = '\0';
    if (bytesReceived < 0 || bytesReceived > MAX_DNS_SIZE || nextByte < 0 || nameEnd < nextByte || nameEnd > bytesReceived) {
        return parseError("++ invalid record: truncated name");
    }
    while (true) {
        if (currentInt < 0 || currentInt >= bytesReceived)
            return parseError("++ invalid record: truncated name");

        if (hasJumped == false && currentInt >= nameEnd)
            return parseError("++ invalid record: truncated name");

        if (visited[currentInt])
            return parseError("++ invalid record: jump loop");
        visited[currentInt] = true;
        unsigned char labelLength = (unsigned char)responseBuffer[currentInt];
        if ((labelLength & 0xC0) == 0xC0) {
            if (currentInt + 1 >= bytesReceived || (hasJumped == false && currentInt + 1 >= nameEnd)) {
                return parseError("++ invalid record: truncated jump offset");
            }
            int jumpPosition = ((labelLength & 0x3F) << 8) | (unsigned char)responseBuffer[currentInt + 1];
            if (jumpPosition >= bytesReceived) {
                return parseError("++ invalid record: jump beyond packet boundary");
            }
            if (jumpPosition < (int)sizeof(FixedDNSHeader)) {
                return parseError("++ invalid record: jump into fixed DNS header");
            }
            if (hasJumped == false) {
                nextByte = currentInt + 2;
            }
            currentInt = jumpPosition;
            hasJumped = true;
            continue;
        }
        if ((labelLength & 0xC0) != 0) {
            return parseError("++ invalid record: invalid label length");
        }
        if (labelLength == 0) {
            if (hasJumped == false) {
                nextByte = currentInt + 1;
            }
            if (nameLength == 0) {
                name[nameLength] = '.';
                nameLength++;
            }
            name[nameLength] = '\0';
            return true;
        }
        if (currentInt+ 1 + labelLength > bytesReceived ||
            (hasJumped == false && currentInt + 1 + labelLength > nameEnd)) {
            return parseError("++ invalid record: truncated name");
        }
        expandedSize = expandedSize + 1 + labelLength;
        if (expandedSize > 255) {
            return parseError("++ invalid record: name exceeds maximum length");
        }

        if (nameLength > 0) {
            if (nameLength + 1 >= MAX_DNS_NAME) {
                return parseError("++ invalid record: name exceeds maximum length");
            }
            name[nameLength] = '.';
            nameLength++;
        }
        for (int i = 0; i < labelLength; i++) {
            unsigned char letter = (unsigned char)responseBuffer[currentInt + 1 + i];
            if (letter == '.' || letter == '\\' || letter <= 32 || letter >= 127) {
                if (nameLength + 4 >= MAX_DNS_NAME) {
                    return parseError("++ invalid record: name exceeds maximum length");
                }
                name[nameLength] = '\\';
                nameLength++;
                name[nameLength] = (char)('0' + letter / 100);
                nameLength++;
                name[nameLength] = (char)('0' + (letter / 10) % 10);
                nameLength++;
                name[nameLength] = (char)('0' + letter % 10);
                nameLength++;
            } else {
                if (nameLength + 1 >= MAX_DNS_NAME) {
                    return parseError("++ invalid record: name exceeds maximum length");
                }
                name[nameLength] = (char)letter;
                nameLength++;
            }
        }
		currentInt = currentInt + 1 + labelLength;
        if (hasJumped == false) {
            nextByte = currentInt;
        }
    }
}

bool readQuestions(char* responseBuffer, int bytesReceived, int& nextByte, unsigned int numQuestions) {
    for (unsigned int i = 0; i < numQuestions; i++) {
        if (nextByte >= bytesReceived) {
            return parseError("++ invalid section: not enough records");
        }
        char name[MAX_DNS_NAME];
        if (readName(responseBuffer, bytesReceived, nextByte, name, bytesReceived) == false) {
            return false;
        }
        if (bytesReceived - nextByte < (int)sizeof(QueryHeader)) {
            return parseError("++ invalid record: truncated query header");
        }
        QueryHeader* question = (QueryHeader*)(responseBuffer + nextByte);
        printf("        %s type %u class %u\n", name,
            (unsigned int)ntohs(question->qType),
            (unsigned int)ntohs(question->qClass));
        nextByte = nextByte + sizeof(QueryHeader);
    }
    return true;
}

bool readRecords(char* responseBuffer, int bytesReceived, int& nextByte, unsigned int numRecords) {
    for (unsigned int i = 0; i < numRecords; i++) {
        if (nextByte >= bytesReceived) {
            return parseError("++ invalid section: not enough records");
        }
        char name[MAX_DNS_NAME];
        if (readName(responseBuffer, bytesReceived, nextByte, name, bytesReceived) == false) {
            return false;
        }
        if (bytesReceived - nextByte < (int)sizeof(DNSanswerHdr)) {
            return parseError("++ invalid record: truncated RR answer header");
        }
        DNSanswerHdr* record = (DNSanswerHdr*)(responseBuffer + nextByte);
        unsigned int recordType = ntohs(record->type);
        unsigned int recordClass = ntohs(record->rrClass);
        unsigned long recordTTL = ntohl(record->TTL);
        int valueLength = ntohs(record->len);
        nextByte = nextByte + sizeof(DNSanswerHdr);
        if (valueLength > bytesReceived - nextByte) {
            return parseError("++ invalid record: RR value length stretches the answer beyond packet");
        }
        int valueEnd = nextByte + valueLength;
        if (recordClass == DNS_INET && recordType == DNS_A) {
            if (valueLength != 4) {
                return parseError("++ invalid record: invalid A record length");
            }
            unsigned char* ipAddrBytes = (unsigned char*)(responseBuffer + nextByte);
            printf("        %s A %u.%u.%u.%u TTL = %lu\n", name,
                (unsigned int)ipAddrBytes[0], (unsigned int)ipAddrBytes[1],
                (unsigned int)ipAddrBytes[2], (unsigned int)ipAddrBytes[3], recordTTL);
        } else if (recordClass == DNS_INET &&
            (recordType == DNS_NS || recordType == DNS_CNAME || recordType == DNS_PTR)) {
            char value[MAX_DNS_NAME];
            int namePosition = nextByte;
            if (readName(responseBuffer, bytesReceived, namePosition, value, valueEnd) == false) {
                return false;
            }
            if (namePosition != valueEnd) {
                return parseError("++ invalid record: domain name does not match RR value length");
            }
            const char* typeName = "NS";
            if (recordType == DNS_CNAME) {
                typeName = "CNAME";
            } else if (recordType == DNS_PTR) {
                typeName = "PTR";
            }
            printf("        %s %s %s TTL = %lu\n", name, typeName, value, recordTTL);
        }
        nextByte = valueEnd;
    }
    return true;
}

bool parseResponse(char* responseBuffer, int bytesReceived, USHORT transactionID) {
    if (bytesReceived < (int)sizeof(FixedDNSHeader)) {
        return parseError("++ invalid reply: packet smaller than fixed DNS header");
    }
    if (bytesReceived > MAX_DNS_SIZE) {
        return parseError("++ invalid reply: packet exceeds maximum DNS size");
    }
    FixedDNSHeader* header = (FixedDNSHeader*)responseBuffer;
    USHORT responseID = ntohs(header->ID);
    unsigned int flags = ntohs(header->flags);
    unsigned int numQuestions = ntohs(header->questions);
    unsigned int numAnswers = ntohs(header->answers);
    unsigned int numAuthority = ntohs(header->authority);
    unsigned int numAdditional = ntohs(header->additional);
    printf("  TXID 0x%.4X, flags 0x%.4X, questions %u, answers %u, authority %u, additional %u\n", (unsigned int)responseID, flags, numQuestions, numAnswers, numAuthority, numAdditional);
    if (responseID != transactionID) {
        printf("  ++ invalid reply: TXID mismatch, sent 0x%.4X, received 0x%.4X\n",
            (unsigned int)transactionID, (unsigned int)responseID);
        return false;
    }
    unsigned int rcode = flags & 0x000F;
    if (rcode != 0) {
        printf("  failed with Rcode = %u\n", rcode);
        return false;
    }
    if ((flags & 0x8000) == 0) {
        return parseError("++ invalid reply: response flag is not set");
    }
    if ((flags & 0x7800) != 0) {
        return parseError("++ invalid reply: unsupported opcode");
    }
    printf("  succeeded with Rcode = 0\n");
    int nextByte = sizeof(FixedDNSHeader);
    if (numQuestions != 0) {
        printf("  ------------ [questions] ----------\n");
        if (readQuestions(responseBuffer, bytesReceived, nextByte, numQuestions) == false) {
            return false;
        }
    }
    if (numAnswers != 0) {
        printf("  ------------ [answers] ------------\n");
        if (readRecords(responseBuffer, bytesReceived, nextByte, numAnswers) == false) {
            return false;
        }
    }
    if (numAuthority != 0) {
        printf("  ------------ [authority] ----------\n");
        if (readRecords(responseBuffer, bytesReceived, nextByte, numAuthority) == false) {
            return false;
        }
    }
    if (numAdditional != 0) {
        printf("  ------------ [additional] ---------\n");
        if (readRecords(responseBuffer, bytesReceived, nextByte, numAdditional) == false) {
            return false;
        }
    }
    return true;
}

int queryServer(char* packet, int packetSize, USHORT transactionID, DWORD serverIP) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket error %d\n", WSAGetLastError());
        return 1;
    }
    struct sockaddr_in localAddress;
    memset(&localAddress, 0, sizeof(localAddress));
    localAddress.sin_family = AF_INET;
    localAddress.sin_addr.s_addr = INADDR_ANY;
    localAddress.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&localAddress, sizeof(localAddress)) == SOCKET_ERROR) {
        printf("bind error %d\n", WSAGetLastError());
        closesocket(sock);
        return 1;
    }
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = serverIP;
    server.sin_port = htons(53);
    int lookupResult = 1;
    for (int attemptNum = 0; attemptNum < MAX_ATTEMPTS; attemptNum++) {
        printf("Attempt %d with %d bytes... ", attemptNum, packetSize);
        fflush(stdout);
		DWORD dnsStart = GetTickCount();
        int sentBytes = sendto(sock, packet, packetSize, 0,
            (struct sockaddr*)&server, sizeof(server));
        if (sentBytes == SOCKET_ERROR) {
            printf("socket error %d\n", WSAGetLastError());
            break;
        }
        if (sentBytes != packetSize) {
            printf("++ incomplete UDP request\n");
            break;
        }
        fd_set socketSet;
        FD_ZERO(&socketSet);
        FD_SET(sock, &socketSet);
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        int selectionResult = select(0, &socketSet, NULL, NULL, &timeout);
        if (selectionResult == SOCKET_ERROR) {
            printf("socket error %d\n", WSAGetLastError());
            break;
        }
        if (selectionResult == 0) {
			DWORD dnsFinish = GetTickCount();
			DWORD dnsDuration = dnsFinish - dnsStart;
            printf("timeout in %lu ms\n", dnsDuration);
            continue;
        }
        char responseBuffer[MAX_DNS_SIZE];
        struct sockaddr_in responseAddress;
        memset(&responseAddress, 0, sizeof(responseAddress));
        int responseLength = sizeof(responseAddress);
        int bytesReceived = recvfrom(sock, responseBuffer, MAX_DNS_SIZE, 0,
            (struct sockaddr*)&responseAddress, &responseLength);
        if (bytesReceived == SOCKET_ERROR) {
            printf("socket error %d\n", WSAGetLastError());
            break;
        }
        DWORD dnsFinish = GetTickCount();
        DWORD dnsDuration = dnsFinish - dnsStart;
        printf("response in %lu ms with %d bytes\n", dnsDuration, bytesReceived);
        if (responseLength < (int)sizeof(responseAddress) ||
            responseAddress.sin_family != AF_INET ||
            responseAddress.sin_addr.s_addr != server.sin_addr.s_addr ||
            responseAddress.sin_port != server.sin_port) {
            printf("  ++ invalid reply: unexpected source IP or port\n");
            break;
        }
        if (parseResponse(responseBuffer, bytesReceived, transactionID)) {
            lookupResult = 0;
        }
        else {
            lookupResult = 1;
        }
        break;
    }
    if (closesocket(sock) == SOCKET_ERROR) {
        printf("closesocket error %d\n", WSAGetLastError());
        lookupResult = 1;
    }
    return lookupResult;
}

int runLookup(const char* lookupName, const char* dnsServer) {
    DWORD serverIP = inet_addr(dnsServer);
    if (serverIP == INADDR_NONE) {
        printf("Error: DNS server must be a valid IPv4 address\n");
        return 1;
    }
    char queryName[256];
    USHORT queryType = DNS_A;
    DWORD ipAddr = inet_addr(lookupName);
    if (ipAddr != INADDR_NONE || strcmp(lookupName, "255.255.255.255") == 0) {
        queryType = DNS_PTR;
        DWORD hostIP = ntohl(ipAddr);
        int queryLength = snprintf(queryName, sizeof(queryName), "%lu.%lu.%lu.%lu.in-addr.arpa", hostIP & 0xFFUL, (hostIP >> 8) & 0xFFUL, (hostIP >> 16) & 0xFFUL, (hostIP >> 24) & 0xFFUL);
        if (queryLength < 0 || (size_t)queryLength >= sizeof(queryName)) {
            printf("Error: invalid reverse lookup name\n");
            return 1;
        }
    } else {
        size_t queryLength = strlen(lookupName);
        if (queryLength > 1 && lookupName[queryLength - 1] == '.') {
            queryLength--;
        }
        if (queryLength == 0 || queryLength > 253) {
            printf("Error: lookup name must contain 1 to 253 characters\n");
            return 1;
        }
        memcpy(queryName, lookupName, queryLength);
        queryName[queryLength] = '\0';
    }
    char encodedName[256];
    int nameLength = makeQuestion(encodedName, queryName);
    if (nameLength < 0) {
        printf("Error: invalid DNS name (labels must contain 1 to 63 bytes)\n");
        return 1;
    }
    random_device randomSource;
    uniform_int_distribution<unsigned int> transactionRange(0, 65535);
    USHORT transactionID = (USHORT)transactionRange(randomSource);
    int packetSize = sizeof(FixedDNSHeader) + nameLength + sizeof(QueryHeader);
    char* packet = new char[packetSize];
    memset(packet, 0, packetSize);
    FixedDNSHeader* fixedHeader = (FixedDNSHeader*)packet;
    QueryHeader* questionHeader = (QueryHeader*)(packet + packetSize - sizeof(QueryHeader));
    fixedHeader->ID = htons(transactionID);
    fixedHeader->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    fixedHeader->questions = htons(1);
    fixedHeader->answers = htons(0);
    fixedHeader->authority = htons(0);
    fixedHeader->additional = htons(0);
    memcpy(fixedHeader + 1, encodedName, nameLength);
    questionHeader->qType = htons(queryType);
    questionHeader->qClass = htons(DNS_INET);
    printf("Lookup  : %s\n", lookupName);
    printf("Query   : %s, type %u, TXID 0x%.4X\n", queryName, (unsigned int)queryType, (unsigned int)transactionID);
    printf("Server  : %s\n", dnsServer);
    printf("********************************\n");
    int lookupResult = queryServer(packet, packetSize, transactionID, serverIP);
    delete[] packet;
    return lookupResult;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: <executable.exe> <hostname or IP> <DNS server IP>");
        return 1;
    }
    WSADATA wsaData;
    WORD requestedVersion = MAKEWORD(2, 2);
    int startUpResult = WSAStartup(requestedVersion, &wsaData);
    if (startUpResult != 0) {
        printf("WSAStartup error %d\n", startUpResult);
        return 1;
    }
    int lookupResult = 1;
    try {
        lookupResult = runLookup(argv[1], argv[2]);
    } catch (const exception& error) {
        printf("Error: %s\n", error.what());
    }
    if (WSACleanup() == SOCKET_ERROR) {
        printf("WSACleanup error %d\n", WSAGetLastError());
        lookupResult = 1;
    }
    return lookupResult;
}