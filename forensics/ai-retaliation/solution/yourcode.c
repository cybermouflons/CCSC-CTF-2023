#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_PACKET_SIZE 1500
#define FLAG "CCSC{z1GbE3_pR0t0c01-m4T3_<3}"
#define FLAG_PARTS 5

typedef struct {
    uint8_t frameControl;
    uint8_t sequenceNumber;
    uint16_t destinationAddress;
    uint16_t sourceAddress;
    uint8_t payloadLength;
    uint8_t payload[MAX_PACKET_SIZE - sizeof(uint8_t) - sizeof(uint8_t) - sizeof(uint16_t) - sizeof(uint16_t)];
} ZigbeePacket;

void generateZigbeeTraffic()
{
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for writing
    handle = pcap_open_dead(DLT_IEEE802_15_4, MAX_PACKET_SIZE);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open pcap file for writing.\n");
        return;
    }

    // Create the pcap dump file
    pcap_dumper_t* dumpfile = pcap_dump_open(handle, "zigbee_traffic.pcap");
    if (dumpfile == NULL) {
        fprintf(stderr, "Failed to create pcap dump file.\n");
        pcap_close(handle);
        return;
    }

    // Generate random noise packets
    int numNoisePackets = 1000;
    for (int i = 0; i < numNoisePackets; i++) {
        ZigbeePacket packet;
        packet.frameControl = 0x01; // Example frame control value
        packet.sequenceNumber = rand() % 256; // Randomize sequence numbers for noise packets
        packet.destinationAddress = 0x0001; // Example destination address
        packet.sourceAddress = 0x0002; // Example source address

        // Randomize payload length for noise packets
        packet.payloadLength = rand() % (MAX_PACKET_SIZE - sizeof(ZigbeePacket));

        // Generate random payload data for noise packets
        for (int j = 0; j < packet.payloadLength; j++) {
            packet.payload[j] = rand() % 256;
        }

        // Set packet timestamps
        struct pcap_pkthdr header;
        header.ts.tv_sec = rand() % 10000; // Example random time
        header.ts.tv_usec = 0;
        header.caplen = sizeof(ZigbeePacket) + packet.payloadLength;
        header.len = header.caplen;

        // Write the packet to the pcap file
        pcap_dump((u_char*)dumpfile, &header, (const u_char*)&packet);
    }

    // Calculate flag part size
    int flagLength = strlen(FLAG);
    int flagPartSize = (flagLength + FLAG_PARTS - 1) / FLAG_PARTS;

    // // Generate random flag part positions
    // int flagPartPositions[FLAG_PARTS];
    // for (int i = 0; i < FLAG_PARTS; i++) {
    //     flagPartPositions[i] = i;
    // }
    // for (int i = FLAG_PARTS - 1; i > 0; i--) {
    //     int j = rand() % (i + 1);
    //     int temp = flagPartPositions[i];
    //     flagPartPositions[i] = flagPartPositions[j];
    //     flagPartPositions[j] = temp;
    // }

    // Determine flag part positions
    int flagPartPositions[FLAG_PARTS] = { 0, 1, 2, 3, 4, 5 }; // Set the desired order of flag parts

    // Generate packets with flag parts
    int packetNumber = numNoisePackets + 1;
    for (int i = 0; i < FLAG_PARTS; i++) {
        int partStart = flagPartPositions[i] * flagPartSize;
        int partEnd = partStart + flagPartSize;
        if (partEnd > flagLength) {
            partEnd = flagLength;
        }

        ZigbeePacket packet;
        packet.frameControl = 0x01; // Example frame control value
        packet.sequenceNumber = rand() % 256; // Randomize sequence numbers for flag packets
        packet.destinationAddress = 0x0001; // Example destination address
        packet.sourceAddress = 0x0002; // Example source address

        packet.payloadLength = partEnd - partStart;
        memcpy(packet.payload, &FLAG[partStart], packet.payloadLength);

        // Set packet timestamps
        struct pcap_pkthdr header;
        header.ts.tv_sec = packetNumber + 1336; // Assign sequential timestamp starting from 1337
        header.ts.tv_usec = 0;
        header.caplen = sizeof(ZigbeePacket) + packet.payloadLength;
        header.len = header.caplen;

        // Write the packet to the pcap file
        pcap_dump((u_char*)dumpfile, &header, (const u_char*)&packet);

        packetNumber++;
    }

    // Generate packets with noise data after the flag parts
    char* protocols[] = {
        "HTTP",
        "TCP",
        "FTP",
        "Telnet",
        "SSH"
    };

    int numNoiseProtocols = sizeof(protocols) / sizeof(protocols[0]);
    for (int i = 0; i < numNoiseProtocols; i++) {
        ZigbeePacket packet;
        packet.frameControl = 0x01; // Example frame control value
        packet.sequenceNumber = rand() % 256; // Randomize sequence numbers for noise packets
        packet.destinationAddress = 0x0001; // Example destination address
        packet.sourceAddress = 0x0002; // Example source address

        // Set payload length and generate payload based on the protocol
        if (strcmp(protocols[i], "HTTP") == 0) {
            packet.payloadLength = snprintf((char*)packet.payload, MAX_PACKET_SIZE - sizeof(ZigbeePacket),
                "GET /%s HTTP/1.1\r\nHost: example.com\r\n\r\n", "mesh_login");
        } else if (strcmp(protocols[i], "TCP") == 0) {
            packet.payloadLength = snprintf((char*)packet.payload, MAX_PACKET_SIZE - sizeof(ZigbeePacket),
                "Random TCP data");
        } else if (strcmp(protocols[i], "FTP") == 0) {
            packet.payloadLength = snprintf((char*)packet.payload, MAX_PACKET_SIZE - sizeof(ZigbeePacket),
                "FTP command: STOR %s", "AI_agents_server");
        } else if (strcmp(protocols[i], "Telnet") == 0) {
            packet.payloadLength = snprintf((char*)packet.payload, MAX_PACKET_SIZE - sizeof(ZigbeePacket),
                "telnet -l %s -p %s", "AI_admin", "s3Cr3t_G@t3_T0_h3lL");
        } else if (strcmp(protocols[i], "SSH") == 0) {
            packet.payloadLength = snprintf((char*)packet.payload, MAX_PACKET_SIZE - sizeof(ZigbeePacket),
                "ssh -l %s -p %s", "AI_admin", "s3Cr3t_G@t3_T0_h3lL");
        }

        // Set packet timestamps
        struct pcap_pkthdr header;
        header.ts.tv_sec = packetNumber + 1336; // Assign sequential timestamp starting from 1337
        header.ts.tv_usec = 0;
        header.caplen = sizeof(ZigbeePacket) + packet.payloadLength;
        header.len = header.caplen;

        // Write the packet to the pcap file
        pcap_dump((u_char*)dumpfile, &header, (const u_char*)&packet);

        packetNumber++;
    }

    // Close the pcap dump file and handle
    pcap_dump_close(dumpfile);
    pcap_close(handle);
}

int main()
{
    srand(time(NULL));

    generateZigbeeTraffic();

    return 0;
}
